/*
 * B431 DfuSe staging writer.
 *
 * Usage:
 *   dfu-write OUTDIR TAG HEX_ADDRESS FILE BUS PORT...
 *
 * AirPower/B431 address map used by the Python runner:
 *   - DfuSe address 0x30000000 aliases console/NVS address 0x90000000.
 *   - DfuSe address 0x30400000 aliases console/external-flash address
 *     0x90400000, the firmware-update staging area at external offset 0x400000.
 *   - Both destinations are 4 KiB flash sectors.  The preceding application
 *     console erases a sector before this helper writes a complete sector
 * image.
 *
 * The helper performs DfuSe SET_ADDRESS followed by bounded DNLOAD blocks of at
 * most 1 KiB each and at most 16 KiB total.  Before an OUT transfer it verifies
 * the USB VID:PID, product and serial strings, active configuration, DfuSe
 * interface class, and physical bus/port path.  It never erases, unprotects,
 * detaches, or resets the device.
 */

#include <errno.h>
#include <libusb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* The Apple VID is shared by many devices; PID 1404 is used by both B431 USB
 * personalities, so the product and serial strings below are also required. */
#define B431_VID 0x05ACu
#define B431_PID 0x1404u
#define B431_DFU_PRODUCT "B431 DFU interface"
#define B431_DFU_SERIAL "FFFFFFFEFFFF"

/* The runner uses two DfuSe external-flash destinations: the 4 KiB manifest at
 * 0x30000000 and a 12 KiB staging transaction beginning at 0x30400000.  Keep the
 * bound at the latter rather than permitting the entire address mask. */
#define EXTERNAL_ALIAS_BASE 0x30000000u
#define EXTERNAL_ALIAS_LAST 0x30400000u
#define SECTOR_ALIGNMENT 0x0FFFu

/* The two host writes are a 4 KiB manifest sector and a 12 KiB padded staging
 * image; 16 KiB is therefore the required convenience bound, not a flash erase
 * block size.  The B431 staging area is eight sectors, but this helper writes
 * only the complete image supplied by the Python runner. */
#define MAX_IMAGE_SIZE 16384u

/* wTransferSize is normally 1024 bytes on the B431.  The descriptor value is
 * still parsed dynamically; this constant is a defensive upper bound. */
#define MAX_TRANSFER_SIZE 1024u

/* Evidence logs are JSONL with hexadecimal payloads.  Bound each record so a
 * bad libusb length cannot create an unbounded host-side log write. */
#define MAX_LOG_HEX_BYTES 2048

/* libusb_get_port_numbers() accepts at most eight entries.  The observed B431
 * topology is much shorter, so this is an API-size bound rather than a device
 * topology assumption. */
#define MAX_PORT_DEPTH 8

/* USB string indexes are one byte and the B431 identity strings are short. */
#define STRING_BUFFER_SIZE 256u

/* Run-directory paths are project-local; refuse truncation instead of writing
 * an evidence file under the wrong name. */
#define PATH_BUFFER_SIZE 2048u

/* Control transfers are short command/status exchanges.  The B431 normally
 * responds immediately; five seconds only bounds a temporarily unavailable
 * device so the Python runner can perform its own retry and recovery policy. */
#define CONTROL_TIMEOUT_MS 5000

/* DFU advertises its busy timeout in GET_STATUS.  Clamp even a malformed
 * 24-bit value before converting it to nanosleep's seconds/nanoseconds. */
#define MAX_DEVICE_WAIT_MS 5000u

/* Empirical B431 transaction bounds: enough GET_STATUS rounds for a sector
 * write to become write-idle, while preventing an infinite busy loop. */
#define STATUS_POLL_LIMIT 20
#define IDLE_POLL_LIMIT 10

/* DfuSe requests use class-specific interface recipients.  The high bits make
 * 0x21 a host-to-device class request and 0xA1 a device-to-host class request.
 * Their wIndex low byte selects the verified interface number zero. */
enum dfu_request_type {
    DFU_REQUEST_OUT = 0x21,
    DFU_REQUEST_IN = 0xA1,
};

/* Standard DFU bRequest values used by the transfer state machine. */
enum dfu_request {
    DFU_REQUEST_DNLOAD = 1,
    DFU_REQUEST_GET_STATUS = 3,
    DFU_REQUEST_CLEAR_STATUS = 4,
    DFU_REQUEST_GET_STATE = 5,
    DFU_REQUEST_ABORT = 6,
};

/* Standard DFU bState values observed on the B431.  Names follow the state
 * machine transitions rather than attempting to infer completion from bStatus
 * alone.  The B431 also briefly reports states 8..12 after some transactions;
 * wait_for_idle() treats that empirical range as clearable with CLEAR_STATUS.
 */
enum dfu_state {
    DFU_STATE_IDLE = 0x02,
    DFU_STATE_WRITE_BUSY = 0x04,
    DFU_STATE_WRITE_IDLE = 0x05,
    DFU_STATE_MANIFEST = 0x07,
    DFU_STATE_UPLOAD_IDLE = 0x09,
    DFU_STATE_ERROR = 0x0A,
};

/* USB DFU interface identity values from the USB DFU class specification. */
#define USB_CLASS_APPLICATION_SPECIFIC 0xFEu
#define USB_DFU_SUBCLASS 0x01u
#define USB_DFU_PROTOCOL_DFU_MODE 0x02u

/* DfuSe places a functional descriptor after the standard interface descriptor.
 * Its layout is: bLength[0], bDescriptorType[1], bmAttributes[2],
 * wDetachTimeOut[3:4], wTransferSize[5:6], followed by vendor extension bytes.
 * The B431 exposes a nine-byte form, so nine is an empirical device bound as
 * well as enough space for every field consumed below. */
#define DFU_FUNCTIONAL_DESCRIPTOR_TYPE 0x21u
#define DFU_ATTRIBUTE_DOWNLOAD_CAPABLE 0x01u
#define B431_FUNCTIONAL_DESCRIPTOR_SIZE 9

/* Every USB descriptor needs enough bytes for bLength and bDescriptorType. */
#define MIN_USB_DESCRIPTOR_SIZE 2

/* The first byte of a five-byte DfuSe SET_ADDRESS DNLOAD command.  It is
 * numerically equal to the class request type but lives in the data payload. */
#define DFU_SET_ADDRESS_COMMAND 0x21u

/* Standard DFU GET_STATUS response layout in bytes. */
#define DFU_STATUS_RESPONSE_SIZE 6
#define DFU_STATUS_INDEX 0
#define DFU_POLL_TIMEOUT_LOW_INDEX 1
#define DFU_POLL_TIMEOUT_MIDDLE_INDEX 2
#define DFU_POLL_TIMEOUT_HIGH_INDEX 3
#define DFU_STATE_INDEX 4

/* bStatus values retained from the observed B431 compatibility behavior. */
#define DFU_STATUS_OK 0u
#define B431_STATUS_ERR_ADDRESS 8u

/* The B431 can report standard error/manifest-wait states and vendor states in
 * this empirical range; the original accepted recovery clears them and retries.
 */
#define DFU_CLEARABLE_STATE_FIRST 8u
#define DFU_CLEARABLE_STATE_LAST 12u

struct options {
    const char* run_directory;
    const char* label;
    const char* image_path;
    uint32_t address;
    uint8_t bus;
    uint8_t ports[MAX_PORT_DEPTH];
    int port_count;
};

struct image {
    unsigned char data[MAX_IMAGE_SIZE];
    size_t size;
};

struct usb_resources {
    libusb_context* context;
    libusb_device** devices;
    libusb_device* device;
    libusb_device_handle* handle;
    bool interface_claimed;
};

struct dfu_connection {
    libusb_device_handle* handle;
    FILE* evidence;
};

struct dfu_status {
    uint8_t status;
    uint8_t state;
};

static void log_control_transfer(FILE* evidence, const char* direction, uint8_t request_type,
                                 uint8_t request, uint16_t value, uint16_t requested, int result,
                                 const unsigned char* data) {
    fprintf(evidence,
            "{\"kind\":\"%s\",\"rt\":%u,\"req\":%u,\"value\":%u,"
            "\"requested\":%d,\"result\":%d,\"hex\":\"",
            direction, request_type, request, value, requested, result);

    int limit = result;
    if (limit > MAX_LOG_HEX_BYTES) {
        limit = MAX_LOG_HEX_BYTES;
    }

    for (int index = 0; index < limit; index++) {
        fprintf(evidence, "%02x", data[index]);
    }

    fprintf(evidence, "\"}\n");
    fflush(evidence);
}

static int control_transfer(struct dfu_connection* connection, uint8_t request_type,
                            uint8_t request, uint16_t value, unsigned char* data, uint16_t size) {
    int result = libusb_control_transfer(connection->handle, request_type, request, value, 0, data,
                                         size, CONTROL_TIMEOUT_MS);

    log_control_transfer(connection->evidence, request_type == DFU_REQUEST_OUT ? "out" : "in",
                         request_type, request, value, size, result, data);

    return result;
}

static bool get_status(struct dfu_connection* connection, struct dfu_status* status) {
    unsigned char response[DFU_STATUS_RESPONSE_SIZE] = {0};
    int result = control_transfer(connection, DFU_REQUEST_IN, DFU_REQUEST_GET_STATUS, 0, response,
                                  sizeof(response));

    if (result != (int) sizeof(response)) {
        return false;
    }

    /* GET_STATUS returns bStatus, a 24-bit little-endian poll timeout, bState,
     * and an optional string index.  Only timeout and state control this writer.
     */
    unsigned wait_ms = (unsigned) response[DFU_POLL_TIMEOUT_LOW_INDEX] |
                       ((unsigned) response[DFU_POLL_TIMEOUT_MIDDLE_INDEX] << 8) |
                       ((unsigned) response[DFU_POLL_TIMEOUT_HIGH_INDEX] << 16);
    if (wait_ms > MAX_DEVICE_WAIT_MS) {
        wait_ms = MAX_DEVICE_WAIT_MS;
    }

    if (response[DFU_STATE_INDEX] == DFU_STATE_WRITE_BUSY) {
        struct timespec delay = {
            .tv_sec = wait_ms / 1000u,
            .tv_nsec = (long) (wait_ms % 1000u) * 1000000L,
        };
        nanosleep(&delay, NULL);
    }

    status->status = response[DFU_STATUS_INDEX];
    status->state = response[DFU_STATE_INDEX];
    return true;
}

static bool clear_status(struct dfu_connection* connection) {
    return control_transfer(connection, DFU_REQUEST_OUT, DFU_REQUEST_CLEAR_STATUS, 0, NULL, 0) == 0;
}

static bool get_state(struct dfu_connection* connection, uint8_t* state) {
    unsigned char response = 0;
    int result = control_transfer(connection, DFU_REQUEST_IN, DFU_REQUEST_GET_STATE, 0, &response,
                                  sizeof(response));

    if (result != (int) sizeof(response)) {
        return false;
    }

    *state = response;
    return true;
}

static bool parse_long(const char* text, long minimum, long maximum, long* value) {
    char* end = NULL;
    errno = 0;
    long parsed = strtol(text, &end, 0);

    if (errno != 0 || end == text || *end != '\0') {
        return false;
    }
    if (parsed < minimum || parsed > maximum) {
        return false;
    }

    *value = parsed;
    return true;
}

static bool parse_options(int argc, char** argv, struct options* options) {
    if (argc < 7) {
        fprintf(stderr, "Usage: %s OUTDIR TAG HEX_ADDRESS FILE BUS PORT...\n", argv[0]);
        return false;
    }

    options->run_directory = argv[1];
    options->label = argv[2];
    options->image_path = argv[4];

    char* address_end = NULL;
    errno = 0;
    unsigned long address = strtoul(argv[3], &address_end, 16);
    if (errno != 0 || address_end == argv[3] || *address_end != '\0' || address > UINT32_MAX) {
        fprintf(stderr, "invalid hexadecimal address: %s\n", argv[3]);
        return false;
    }
    options->address = (uint32_t) address;

    long bus = 0;
    if (!parse_long(argv[5], 0, UINT8_MAX, &bus)) {
        fprintf(stderr, "invalid USB bus: %s\n", argv[5]);
        return false;
    }
    options->bus = (uint8_t) bus;

    options->port_count = argc - 6;
    if (options->port_count < 1 || options->port_count > MAX_PORT_DEPTH) {
        fprintf(stderr, "USB port path must contain 1..%d ports\n", MAX_PORT_DEPTH);
        return false;
    }

    for (int index = 0; index < options->port_count; index++) {
        long port = 0;
        if (!parse_long(argv[6 + index], 0, UINT8_MAX, &port)) {
            fprintf(stderr, "invalid USB port: %s\n", argv[6 + index]);
            return false;
        }
        options->ports[index] = (uint8_t) port;
    }

    return true;
}

static bool read_image(const char* path, struct image* image) {
    FILE* file = fopen(path, "rb");
    if (file == NULL) {
        perror(path);
        return false;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        perror(path);
        fclose(file);
        return false;
    }

    long length = ftell(file);
    if (length < 0) {
        perror(path);
        fclose(file);
        return false;
    }

    if (length == 0 || (unsigned long) length > MAX_IMAGE_SIZE) {
        fprintf(stderr, "image length %ld is outside 1..%u bytes\n", length, MAX_IMAGE_SIZE);
        fclose(file);
        return false;
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        perror(path);
        fclose(file);
        return false;
    }

    if (fread(image->data, 1, (size_t) length, file) != (size_t) length) {
        perror(path);
        fclose(file);
        return false;
    }

    if (fclose(file) != 0) {
        perror(path);
        return false;
    }

    image->size = (size_t) length;
    return true;
}

static bool open_evidence_log(const struct options* options, FILE** evidence) {
    char path[PATH_BUFFER_SIZE];
    int length = snprintf(path, sizeof(path), "%s/control-%s-%08x.jsonl", options->run_directory,
                          options->label, options->address);

    if (length < 0 || (size_t) length >= sizeof(path)) {
        fprintf(stderr, "evidence log path is too long\n");
        return false;
    }

    *evidence = fopen(path, "wx");
    if (*evidence == NULL) {
        perror(path);
        return false;
    }

    return true;
}

static bool verify_topology(libusb_device* device, const struct options* options) {
    uint8_t actual_ports[MAX_PORT_DEPTH] = {0};
    int depth = libusb_get_port_numbers(device, actual_ports, MAX_PORT_DEPTH);
    if (depth < 0) {
        fprintf(stderr, "could not read the USB port path\n");
        return false;
    }

    uint8_t bus = libusb_get_bus_number(device);
    printf("bus=%u path=", bus);
    for (int index = 0; index < depth; index++) {
        printf("%s%u", index == 0 ? "" : ".", actual_ports[index]);
    }
    printf("\n");

    if (bus != options->bus || depth != options->port_count ||
        memcmp(actual_ports, options->ports, (size_t) depth) != 0) {
        fprintf(stderr, "physical USB topology does not match the requested device\n");
        return false;
    }

    return true;
}

static bool find_b431_device(struct usb_resources* usb) {
    libusb_device* match = NULL;
    int matches = 0;
    ssize_t count = libusb_get_device_list(usb->context, &usb->devices);

    for (ssize_t index = 0; index < count; index++) {
        struct libusb_device_descriptor descriptor;
        if (libusb_get_device_descriptor(usb->devices[index], &descriptor) != 0) {
            continue;
        }
        if (descriptor.idVendor == B431_VID && descriptor.idProduct == B431_PID) {
            matches++;
            match = usb->devices[index];
        }
    }

    if (matches != 1) {
        fprintf(stderr, "expected one B431 USB device, found %d\n", matches);
        return false;
    }

    usb->device = match;
    return true;
}

static unsigned parse_transfer_size(libusb_device* device) {
    struct libusb_config_descriptor* config = NULL;
    unsigned transfer_size = 0;

    if (libusb_get_active_config_descriptor(device, &config) != 0) {
        return 0;
    }

    /* The B431 DFU enumeration has one active configuration, one interface, and
     * one alternate setting.  Checking the exact shape prevents accidentally
     * parsing a functional descriptor from another interface or configuration. */
    if (config->bConfigurationValue == 1 && config->bNumInterfaces == 1 &&
        config->interface[0].num_altsetting == 1) {
        const struct libusb_interface_descriptor* interface = &config->interface[0].altsetting[0];

        /* USB DFU identity:
         *   class    0xFE = application-specific class,
         *   subclass 0x01 = DFU,
         *   protocol 0x02 = DFU-mode (rather than runtime-mode) interface.
         * The B431 changes from its CDC personality to this DFU-mode interface. */
        if (interface->bInterfaceNumber == 0 && interface->bAlternateSetting == 0 &&
            interface->bInterfaceClass == USB_CLASS_APPLICATION_SPECIFIC &&
            interface->bInterfaceSubClass == USB_DFU_SUBCLASS &&
            interface->bInterfaceProtocol == USB_DFU_PROTOCOL_DFU_MODE) {
            /* Class-specific descriptors trail the standard interface descriptor.
             * Each begins with its own byte length, so advance by bLength rather
             * than assuming a fixed-size tail or a particular descriptor order. */
            for (int offset = 0; offset + MIN_USB_DESCRIPTOR_SIZE < interface->extra_length &&
                                 interface->extra[offset] >= MIN_USB_DESCRIPTOR_SIZE;
                 offset += interface->extra[offset]) {
                int descriptor_size = interface->extra[offset];
                if (offset + descriptor_size > interface->extra_length) {
                    break;
                }

                /* bDescriptorType 0x21 identifies a DFU functional descriptor.
                 * bmAttributes bit 0 means the device accepts host-to-device DNLOAD;
                 * without it there is no staging write to negotiate. */
                if (descriptor_size >= B431_FUNCTIONAL_DESCRIPTOR_SIZE &&
                    interface->extra[offset + 1] == DFU_FUNCTIONAL_DESCRIPTOR_TYPE &&
                    (interface->extra[offset + 2] & DFU_ATTRIBUTE_DOWNLOAD_CAPABLE) != 0) {
                    /* wTransferSize occupies bytes 5 and 6 in little-endian order.  It
                     * is the device-defined maximum DNLOAD payload, not the total image
                     * size and not a USB endpoint MTU.  The B431 reports 1024 bytes. */
                    transfer_size = (unsigned) interface->extra[offset + 5] |
                                    ((unsigned) interface->extra[offset + 6] << 8);
                }
            }
        }
    }

    libusb_free_config_descriptor(config);

    if (transfer_size == 0 || transfer_size > MAX_TRANSFER_SIZE) {
        fprintf(stderr, "invalid DfuSe download transfer size: %u\n", transfer_size);
        return 0;
    }

    printf("wTransferSize=%u\n", transfer_size);
    return transfer_size;
}

static bool read_usb_string(libusb_device_handle* handle, uint8_t descriptor_index, char* output,
                            size_t output_size) {
    int length = libusb_get_string_descriptor_ascii(handle, descriptor_index,
                                                    (unsigned char*) output, (int) output_size - 1);
    if (length < 0) {
        return false;
    }

    output[length] = '\0';
    return true;
}

static bool open_and_verify_device(struct usb_resources* usb) {
    if (libusb_open(usb->device, &usb->handle) != 0) {
        fprintf(stderr, "could not open the B431 DFU interface\n");
        return false;
    }

    char serial[STRING_BUFFER_SIZE];
    char product[STRING_BUFFER_SIZE];
    struct libusb_device_descriptor descriptor;

    if (libusb_get_device_descriptor(usb->device, &descriptor) != 0 ||
        !read_usb_string(usb->handle, descriptor.iSerialNumber, serial, sizeof(serial)) ||
        !read_usb_string(usb->handle, descriptor.iProduct, product, sizeof(product))) {
        fprintf(stderr, "could not read the B431 USB identity strings\n");
        return false;
    }

    if (strcmp(serial, B431_DFU_SERIAL) != 0) {
        fprintf(stderr, "unexpected B431 serial: %s\n", serial);
        return false;
    }
    if (strcmp(product, B431_DFU_PRODUCT) != 0) {
        fprintf(stderr, "unexpected B431 product: %s\n", product);
        return false;
    }

    printf("serial=%s product=%s\n", serial, product);

    if (libusb_claim_interface(usb->handle, 0) != 0) {
        fprintf(stderr, "could not claim the B431 DFU interface\n");
        return false;
    }

    usb->interface_claimed = true;
    return true;
}

static bool wait_for_idle(struct dfu_connection* connection) {
    for (int attempt = 0; attempt < IDLE_POLL_LIMIT; attempt++) {
        struct dfu_status status;
        if (!get_status(connection, &status)) {
            return false;
        }
        if (status.state == DFU_STATE_IDLE) {
            return true;
        }
        /* State 8 is manifest-wait-reset, 10 is the standard DFU error, and the
         * B431 also exposes neighboring vendor states.  The accepted recovery
         * sends CLEAR_STATUS and polls again rather than resetting the device. */
        if (status.state >= DFU_CLEARABLE_STATE_FIRST && status.state <= DFU_CLEARABLE_STATE_LAST &&
            !clear_status(connection)) {
            return false;
        }
    }

    fprintf(stderr, "B431 DFU interface did not return to idle\n");
    return false;
}

static bool set_download_address(struct dfu_connection* connection, uint32_t address) {
    /* DfuSe encodes SET_ADDRESS as a five-byte DNLOAD command in block zero:
     * prefix 0x21 followed by the 32-bit flash address in little-endian order. */
    unsigned char command[5] = {
        DFU_SET_ADDRESS_COMMAND,
        (unsigned char) (address & 0xFFu),
        (unsigned char) ((address >> 8) & 0xFFu),
        (unsigned char) ((address >> 16) & 0xFFu),
        (unsigned char) ((address >> 24) & 0xFFu),
    };

    if (control_transfer(connection, DFU_REQUEST_OUT, DFU_REQUEST_DNLOAD, 0, command,
                         sizeof(command)) != (int) sizeof(command)) {
        fprintf(stderr, "DfuSe SET_ADDRESS request failed\n");
        return false;
    }

    for (int attempt = 0; attempt < STATUS_POLL_LIMIT; attempt++) {
        struct dfu_status status;
        if (!get_status(connection, &status)) {
            return false;
        }
        if (status.status != DFU_STATUS_OK) {
            fprintf(stderr, "DfuSe SET_ADDRESS bStatus=%u\n", status.status);
            return false;
        }
        if (status.state == DFU_STATE_WRITE_IDLE) {
            break;
        }
        if (status.state != DFU_STATE_WRITE_BUSY) {
            fprintf(stderr, "DfuSe SET_ADDRESS entered unexpected state %u\n", status.state);
            return false;
        }
    }

    uint8_t state = 0;
    if (control_transfer(connection, DFU_REQUEST_OUT, DFU_REQUEST_ABORT, 0, NULL, 0) != 0 ||
        !get_state(connection, &state) || state != DFU_STATE_IDLE) {
        fprintf(stderr, "DfuSe SET_ADDRESS did not return to idle\n");
        return false;
    }

    return true;
}

static bool write_image(struct dfu_connection* connection, struct image* image,
                        unsigned transfer_size, uint32_t address, size_t image_size) {
    /* Block zero carried SET_ADDRESS, and DfuSe reserves/skips block one for
     * that command phase.  The first image byte therefore belongs to block two.
     */
    unsigned block = 2;

    for (size_t offset = 0; offset < image->size; offset += transfer_size) {
        size_t remaining = image->size - offset;
        size_t chunk_size = remaining < transfer_size ? remaining : transfer_size;
        unsigned short chunk = (unsigned short) chunk_size;

        if (control_transfer(connection, DFU_REQUEST_OUT, DFU_REQUEST_DNLOAD, block,
                             image->data + offset, chunk) != (int) chunk) {
            fprintf(stderr, "DfuSe DNLOAD block %u failed\n", block);
            return false;
        }

        bool settled = false;
        for (int attempt = 0; attempt < STATUS_POLL_LIMIT; attempt++) {
            struct dfu_status status;
            if (!get_status(connection, &status)) {
                return false;
            }
            if (status.status != DFU_STATUS_OK) {
                fprintf(stderr, "DfuSe DNLOAD block %u bStatus=%u\n", block, status.status);
                return false;
            }
            if (status.state == DFU_STATE_WRITE_IDLE) {
                settled = true;
                break;
            }
            if (status.state != DFU_STATE_WRITE_BUSY) {
                fprintf(stderr, "DfuSe DNLOAD block %u entered state %u\n", block, status.state);
                return false;
            }
        }

        if (!settled) {
            fprintf(stderr, "DfuSe DNLOAD block %u did not settle\n", block);
            return false;
        }

        printf("block %u @ +0x%04zx ok (%u bytes)\n", block, offset, chunk);
        block++;
    }

    /* A zero-length DNLOAD on the next block marks the transaction boundary.  It
     * is not a USB reset request; the B431 re-enumerates its console interface
     * only after its firmware completes the external-flash write. */
    if (control_transfer(connection, DFU_REQUEST_OUT, DFU_REQUEST_DNLOAD, block, NULL, 0) != 0) {
        fprintf(stderr, "DfuSe end-of-transfer request failed\n");
        return false;
    }

    struct dfu_status status;
    bool finished = false;
    for (int attempt = 0; attempt < STATUS_POLL_LIMIT; attempt++) {
        if (!get_status(connection, &status)) {
            return false;
        }
        /* bStatus 8 is DFU errAddress.  The accepted B431 compatibility path can
         * report it during a final transition, so retain the historical check
         * instead of rejecting every nonzero bStatus at end-of-transfer. */
        if (status.status != DFU_STATUS_OK && status.status != B431_STATUS_ERR_ADDRESS &&
            status.state != DFU_STATE_ERROR) {
            fprintf(stderr, "DfuSe end transfer bStatus=%u state=%u\n", status.status,
                    status.state);
            return false;
        }
        if (status.state == DFU_STATE_MANIFEST || status.state == DFU_STATE_UPLOAD_IDLE ||
            status.state == DFU_STATE_ERROR || status.state == DFU_STATE_IDLE ||
            status.state == DFU_STATE_WRITE_IDLE) {
            finished = true;
            break;
        }
    }

    if (!finished) {
        fprintf(stderr, "DfuSe end transfer did not reach a final state\n");
        return false;
    }

    printf("final state=%u bStatus=%u\n", status.status, status.state);
    fprintf(connection->evidence,
            "{\"kind\":\"summary\",\"address\":\"0x%08x\",\"bytes\":%zu,"
            "\"state\":%u,\"bStatus\":%u}\n",
            address, image_size, status.state, status.status);

    return true;
}

static void release_usb_resources(struct usb_resources* usb) {
    if (usb->interface_claimed) {
        libusb_release_interface(usb->handle, 0);
    }
    if (usb->handle != NULL) {
        libusb_close(usb->handle);
    }
    if (usb->devices != NULL) {
        libusb_free_device_list(usb->devices, 1);
    }
    if (usb->context != NULL) {
        libusb_exit(usb->context);
    }
}

int main(int argc, char** argv) {
    struct options options;
    if (!parse_options(argc, argv, &options)) {
        return 2;
    }

    if (options.address < EXTERNAL_ALIAS_BASE || options.address > EXTERNAL_ALIAS_LAST ||
        (options.address & SECTOR_ALIGNMENT) != 0) {
        fprintf(stderr,
                "address 0x%08x must be 4 KiB aligned and lie within "
                "0x%08x..0x%08x\n",
                options.address, EXTERNAL_ALIAS_BASE, EXTERNAL_ALIAS_LAST);
        return 2;
    }

    struct image image;
    if (!read_image(options.image_path, &image)) {
        return 2;
    }

    FILE* evidence = NULL;
    if (!open_evidence_log(&options, &evidence)) {
        return 2;
    }

    struct usb_resources usb = {0};
    bool success = false;

    do {
        if (libusb_init(&usb.context) != 0) {
            fprintf(stderr, "could not initialize libusb\n");
            break;
        }
        if (!find_b431_device(&usb) || !verify_topology(usb.device, &options)) {
            break;
        }

        unsigned transfer_size = parse_transfer_size(usb.device);
        if (transfer_size == 0) {
            break;
        }
        if (!open_and_verify_device(&usb)) {
            break;
        }

        struct dfu_connection connection = {
            .handle = usb.handle,
            .evidence = evidence,
        };

        if (!wait_for_idle(&connection) || !set_download_address(&connection, options.address) ||
            !write_image(&connection, &image, transfer_size, options.address, image.size)) {
            break;
        }

        success = true;
    } while (false);

    release_usb_resources(&usb);
    if (fclose(evidence) != 0) {
        perror("evidence log");
        success = false;
    }

    return success ? 0 : 1;
}
