/*
 * Copyright (c) 2025 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: Tom St Denis <tom.stdenis@amd.com>
 *
 */
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>

#include "umr.h"
#include "umr_rumr.h"

/**
 * is_did_match - Check if a device ID matches the ASIC
 *
 * @asic: The ASIC structure to check against
 * @did: The device ID to match
 *
 * This helper function attempts to discover an ASIC by the given device ID
 * and verifies if the discovered ASIC name matches the provided ASIC's name.
 * The function temporarily sets quiet mode during the discovery process to
 * suppress error messages.
 *
 * Return: 1 if the device ID matches the ASIC name, 0 otherwise
 */
static int is_did_match(struct umr_asic *asic, unsigned did)
{
	struct umr_asic *tmp;
	int r = 0, q;
	int tryipdiscovery = 0;

	/* Save current quiet mode setting and enable quiet mode during discovery */
	q = asic->options.quiet;
	asic->options.quiet = 1;

	/* Attempt to discover ASIC by device ID */
	tmp = umr_discover_asic_by_did(&asic->options, did, asic->err_msg, &tryipdiscovery);
	if (tmp) {
		/* Check if discovered ASIC name matches the target ASIC name */
		if (!strcmp(tmp->asicname, asic->asicname)) {
			asic->did = did;
			r = 1;
		}
		umr_close_asic(tmp);
	}
	/* Restore original quiet mode setting */
	asic->options.quiet = q;
	return r;
}

/**
 * find_pci_instance - Find the DRI instance number for a given PCI device
 *
 * @pci_string: PCI bus address string in format "dddd:bb:ss.f"
 *              (domain:bus:slot.function)
 *
 * This function scans the /sys/kernel/debug/dri directory to find the DRI
 * instance number associated with a specific PCI device address. It filters
 * out non-AMDGPU devices and render nodes (instance >= 128).
 *
 * The function prefers devices with IP discovery support, but will fall back
 * to pre-IP discovery hardware if no better match is found.
 *
 * Return: The DRI instance number (>= 0) on success, -1 on failure
 */
static int find_pci_instance(const char* pci_string)
{
	DIR *dir;
	struct dirent *dir_entry;
	int saved = -1;

	/* Open the debugfs DRI directory to enumerate DRI devices */
	dir = opendir("/sys/kernel/debug/dri");
	if (dir == NULL) {
		if (geteuid() != 0)
			fprintf(stderr, "[ERROR]: Could not open debugfs DRI tree because UMR was not invoked as root.\n");
		else
			fprintf(stderr, "[ERROR]: Could not open debugfs DRI tree because DRI directory doesn't exist likely because debugfs was not enabled.\n");
		perror("[ERROR]: Couldn't open DRI under debugfs");
		exit(-1);
	}

	/* Iterate through all DRI devices to find matching PCI address */
	while ((dir_entry = readdir(dir)) != NULL) {
		char device[512], name[512];
		int parsed_device;
		FILE *f;

		/* Skip current directory, parent directory, and PCI bus entries (contain ':') */
		if (strcmp(dir_entry->d_name, ".") == 0 ||
		    strcmp(dir_entry->d_name, "..") == 0 ||
			strchr(dir_entry->d_name, ':'))
			continue;

		/* Filter out non-AMDGPU DRI directories by checking for amdgpu_regs2 */
		snprintf(name, sizeof(name), "/sys/kernel/debug/dri/%s/amdgpu_regs2",
			dir_entry->d_name);
		f = fopen(name, "r");
		if (!f)
			continue;
		fclose(f);

		/* Read the PCI bus address from the device name file */
		snprintf(name, sizeof(name), "/sys/kernel/debug/dri/%s/name",
			dir_entry->d_name);

		f = fopen(name, "r");
		if (!f)
			continue;

		/* Parse the PCI device address from the name file */
		device[sizeof(device) - 1] = 0;
		parsed_device = fscanf(f, "%*s %255s", device);
		fclose(f);

		if (parsed_device != 1)
			continue;

		/* Strip off "dev=" prefix for kernels > 4.7 */
		if (strstr(device, "dev="))
			memmove(device, device + 4, strlen(device) - 3);

		/* Check if this device matches the requested PCI address */
		if (strcmp(pci_string, device) == 0) {
			/* Convert directory name to instance number */
			int inst = atoi(dir_entry->d_name);

			/* Exclude render nodes (instances >= 128) */
			if (inst < 128) {
				/* Save this instance as a fallback for pre-IP discovery hardware */
				saved = inst;

				/* Check if this device supports IP discovery (preferred) */
				snprintf(name, sizeof(name), "/sys/class/drm/card%s/device/ip_discovery/die/0/num_ips", dir_entry->d_name);
				f = fopen(name, "r");
				if (!f)
					continue; /* No IP discovery, keep looking */
				fclose(f);
				/* Found device with IP discovery support, use this one */
				break;
			}
		}
	}
	closedir(dir);
	return saved;
}


/**
 * umr_discover_asic - Discover and initialize an ASIC device in the system
 *
 * @options: Structure containing discovery options and configuration settings
 * @errout: Error output callback function for reporting diagnostics
 *
 * This function performs comprehensive ASIC device discovery and initialization
 * using multiple detection methods in priority order:
 *
 * 1. Virtual device: If @options->dev_name starts with '.', discovers a virtual
 *    ASIC for offline analysis (e.g., ".navi10" for a virtual Navi10 device)
 *
 * 2. PCI bus address: If @options->pci fields are set, locates the device by
 *    specific PCI domain:bus:slot.function address
 *
 * 3. DRI instance: If @options->instance >= 0, uses the specified DRI device
 *    instance number (e.g., /sys/kernel/debug/dri/0)
 *
 * 4. Device name: If @options->dev_name is set, discovers by ASIC name
 *    (e.g., "navi10", "vega20")
 *
 * 5. Device ID: Discovers using PCI device ID read from sysfs
 *
 * The function also handles:
 * - No-kernel mode for offline analysis using serialized ASIC files
 * - PCI memory mapping when @options->use_pci is set
 * - Opening debugfs file descriptors for hardware access
 * - IP discovery table detection for modern ASICs
 * - Validation of amdgpu kernel module presence
 *
 * Return: Pointer to initialized umr_asic structure on success, NULL on failure
 */
struct umr_asic *umr_discover_asic(struct umr_options *options, umr_err_output errout)
{
	char driver[512], name[256], fname[256];
	FILE *f;
	unsigned did = 0;
	struct umr_asic *asic = NULL;
	long trydid = options->forcedid;
	int busmatch = 0, parsed_did, need_config_scan = 0;
	int tryipdiscovery = 0;

	/* Handle virtual device mode (dev_name starts with '.') */
	if (options->dev_name[0] == '.') {
		options->is_virtual = 1;
		/* Skip the leading '.' and discover by the ASIC name */
		asic = umr_discover_asic_by_name(options, options->dev_name + 1, errout);
		if (asic)
			asic->options = *options;
		return asic;
	}

	/* Handle discovery by specific PCI bus address (domain:bus:slot.func) */
	if (options->pci.domain || options->pci.bus ||
	    options->pci.slot || options->pci.func) {
		int parsed_did, inst = -1;
		unsigned long did;

		/* Format PCI address string */
		snprintf(options->pci.name, sizeof(options->pci.name), "%04x:%02x:%02x.%x",
			options->pci.domain, options->pci.bus, options->pci.slot,
			options->pci.func);

		/* Find the corresponding DRI instance number for this PCI device */
		if (!options->no_kernel)
			inst = find_pci_instance(options->pci.name);

		if (inst >= 0) {
			options->instance = inst;

			/* Read the PCI device ID from sysfs */
			snprintf(driver, sizeof(driver), "/sys/bus/pci/devices/%s/device", options->pci.name);
			f = fopen(driver, "r");
			if (!f) {
				if (!options->quiet) perror("Cannot open PCI device name under sysfs (is a display attached?)");
				return NULL;
			}
			parsed_did = fscanf(f, "0x%04lx", &did);
			trydid = did;
			fclose(f);
			if (parsed_did != 1) {
				if (!options->quiet) printf("Could not read device id");
				return NULL;
			}

			/* In no-kernel mode, try loading a serialized ASIC file (.sasic) */
			if (options->no_kernel) {
				struct rumr_buffer *buf;
				char fname[32];

				/* Construct filename from device ID */
				sprintf(fname, "0x%"PRIx32".sasic", (uint32_t)did);
				buf = rumr_load_serialized_asic(fname, options->database_path);
				if (buf) {
					asic = rumr_parse_serialized_asic(buf);
					rumr_buffer_free(buf);
					if (asic) {
						asic->options = *options;
					}
				}
			}
		}
	}

	/* In no-kernel mode with a device name specified, try loading by name */
	if (!asic && options->no_kernel && options->dev_name[0]) {
		asic = umr_discover_asic_by_name(options, options->dev_name, errout);
	}

	/* Attempt to read device ID via debugfs config scan */
	if (!asic && options->instance >= 0 && !options->no_kernel) {
		asic = calloc(1, sizeof *asic);
		if (asic) {
			asic->instance = options->instance;
			asic->options  = *options;
			/* Scan gca config to obtain device ID */
			if (!umr_scan_config(asic, 0) && asic->config.pci.device)
				trydid = asic->config.pci.device;
			/* Free temporary ASIC structure (will be recreated later) */
			umr_free_asic(asic);
			asic = NULL;
		}
	}

	/* When kernel mode is enabled, read device info from debugfs */
	if (!options->no_kernel) {
		snprintf(name, sizeof(name)-1, "/sys/kernel/debug/dri/%d/name", options->instance);
		f = fopen(name, "r");

		/* Handle error opening debugfs DRI name file */
		if (!f && options->instance >= 0 && !options->no_kernel && !options->use_pci) {
			int found = 0;
			if (!options->quiet) {
				/* Check if amdgpu kernel module is loaded */
				f = popen("lsmod | grep ^amdgpu", "r");
				while (fgets(name, sizeof(name)-1, f)) {
					if (strstr(name, "amdgpu"))
						found = 1;
				}
				pclose(f);

				perror("Cannot open DRI name under debugfs");
				if (!found)
					printf("ERROR: amdgpu.ko is not loaded.\n");
				else
					printf("ERROR: amdgpu.ko is loaded but /sys/kernel/debug/dri/%d/name is not found\n", options->instance);
			}
			return NULL;
		} else if (f) {
			int r;

			/* Read PCI bus address from DRI name file */
			r = fscanf(f, "%*s %s", name);
			fclose(f);
			if (r == 1) {
				/* Strip off "dev=" prefix for kernels > 4.7 */
				if (strstr(name, "dev="))
					memmove(name, name+4, strlen(name)-3);

				/* Parse PCI address if not already set */
				if (!strlen(options->pci.name)) {
					strcpy(options->pci.name, name);
					sscanf(name, "%04x:%02x:%02x.%x",
						&options->pci.domain,
						&options->pci.bus,
						&options->pci.slot,
						&options->pci.func);
					need_config_scan = 1;
				}
			}
		}

		/* If device ID wasn't determined yet, read it from sysfs */
		if (trydid < 0) {
			snprintf(driver, sizeof(driver)-1, "/sys/bus/pci/devices/%s/device", name);
			f = fopen(driver, "r");
			if (!f) {
				if (!options->quiet) perror("Cannot open PCI device name under sysfs (is a display attached?)");
				return NULL;
			}

			/* Read PCI device ID */
			parsed_did = fscanf(f, "0x%04x", &did);
			fclose(f);
			if (parsed_did != 1) {
				if (!options->quiet) printf("Could not read device id");
				return NULL;
			}
			/* Discover ASIC using the device ID */
			asic = umr_discover_asic_by_did(options, did, errout, &tryipdiscovery);
		} else {
			/* Device ID is known, proceed with discovery */
			if (options->dev_name[0]) {
				/* Explicit device name provided, use it */
				asic = umr_discover_asic_by_name(options, options->dev_name, errout);
			} else {
				/* Try discovering by device ID */
				asic = umr_discover_asic_by_did(options, trydid, errout, &tryipdiscovery);

				/* If not found but device supports IP discovery, create generic name */
				if (!asic && tryipdiscovery) {
					char buf[32];
					sprintf(buf, "amd%04" PRIx64, (uint64_t)trydid);
					asic = umr_discover_asic_by_name(options, buf, errout);
					if (asic && !options->quiet)
						errout("[WARNING]: Unknown ASIC [%s] should be added to pci.did to get proper name\n", buf);
				}
			}
		}
	}

	/* ASIC successfully discovered, now initialize file descriptors and options */
	if (asic) {
		asic->err_msg = errout;
		memcpy(&asic->options, options, sizeof(*options));

		/* Populate asic->did from the discovered device id.  For ASICs not in
		 * umr's pci.did table (discovered generically by IP discovery / name),
		 * is_did_match() never runs, so asic->did would otherwise stay 0. */
		if (trydid > 0 && !asic->did)
			asic->did = trydid;

		if (!asic->options.no_kernel) {
			/* Open debugfs file descriptors for hardware access */

			/* MMIO register access (prefer regs2 which supports indirect access) */
			snprintf(fname, sizeof(fname)-1, "/sys/kernel/debug/dri/%d/amdgpu_regs2", asic->instance);
			asic->fd.mmio2 = open(fname, O_RDWR);
			if (asic->fd.mmio2 >= 0) {
				asic->fd.mmio = -1;
			} else {
				/* Fall back to legacy regs interface if regs2 not available */
				snprintf(fname, sizeof(fname)-1, "/sys/kernel/debug/dri/%d/amdgpu_regs", asic->instance);
				asic->fd.mmio = open(fname, O_RDWR);
			}

			/* Digital power/thermal (DIDT) register access */
			snprintf(fname, sizeof(fname)-1, "/sys/kernel/debug/dri/%d/amdgpu_regs_didt", asic->instance);
			asic->fd.didt = open(fname, O_RDWR);

			/* PCIe configuration space access */
			snprintf(fname, sizeof(fname)-1, "/sys/kernel/debug/dri/%d/amdgpu_regs_pcie", asic->instance);
			asic->fd.pcie = open(fname, O_RDWR);

			/* System Management Controller (SMC) register access */
			snprintf(fname, sizeof(fname)-1, "/sys/kernel/debug/dri/%d/amdgpu_regs_smc", asic->instance);
			asic->fd.smc = open(fname, O_RDWR);

			/* Hardware sensors (temperature, voltage, power, etc.) */
			snprintf(fname, sizeof(fname)-1, "/sys/kernel/debug/dri/%d/amdgpu_sensors", asic->instance);
			asic->fd.sensors = open(fname, O_RDONLY);

			/* VRAM memory access */
			snprintf(fname, sizeof(fname)-1, "/sys/kernel/debug/dri/%d/amdgpu_vram", asic->instance);
			asic->fd.vram = open(fname, O_RDWR);

			/* Combined GPR and wave data access (preferred for newer kernels) */
			snprintf(fname, sizeof(fname)-1, "/sys/kernel/debug/dri/%d/amdgpu_gprwave", asic->instance);
			asic->fd.gprwave = open(fname, O_RDWR);
			if (asic->fd.gprwave < 0) {
				/* Fall back to separate GPR and wave interfaces for older kernels */
				snprintf(fname, sizeof(fname)-1, "/sys/kernel/debug/dri/%d/amdgpu_gpr", asic->instance);
				asic->fd.gpr = open(fname, O_RDONLY);
				snprintf(fname, sizeof(fname)-1, "/sys/kernel/debug/dri/%d/amdgpu_wave", asic->instance);
				asic->fd.wave = open(fname, O_RDONLY);
			} else {
				asic->fd.gpr = -1;
				asic->fd.wave = -1;
			}

			/* Virtual address to physical address translation */
			snprintf(fname, sizeof(fname)-1, "/sys/kernel/debug/dri/%d/amdgpu_iova", asic->instance);
			asic->fd.iova = open(fname, O_RDWR);

			/* IO memory access */
			snprintf(fname, sizeof(fname)-1, "/sys/kernel/debug/dri/%d/amdgpu_iomem", asic->instance);
			asic->fd.iomem = open(fname, O_RDWR);

			/* GFXOFF state control (power gating for GFX engine) */
			snprintf(fname, sizeof(fname)-1, "/sys/kernel/debug/dri/%d/amdgpu_gfxoff", asic->instance);
			asic->fd.gfxoff = open(fname, O_RDWR);

			/* DRM file descriptor (opened on demand) */
			asic->fd.drm = -1;

			/* NOTE: When adding new file descriptors, update close_asic() and discover_by_did() */
		} else {
			/* No-kernel mode: all file descriptors are closed */
			asic->fd.mmio2 = -1;
			asic->fd.mmio = -1;
			asic->fd.didt = -1;
			asic->fd.pcie = -1;
			asic->fd.smc = -1;
			asic->fd.sensors = -1;
			asic->fd.vram = -1;
			asic->fd.gprwave = -1;
			asic->fd.gpr = -1;
			asic->fd.wave = -1;
			asic->fd.drm = -1;
			asic->fd.iova = -1;
			asic->fd.iomem = -1;
			asic->fd.gfxoff = -1;
		}

		/* Initialize direct PCI memory mapping when requested */
		if (options->use_pci) {
			int use_region;
			void *pcimem_v;
			struct pci_device_iterator *pci_iter;
			pciaddr_t pci_region_addr;

			/* Initialize libpciaccess */
			pci_system_init();
			pci_iter = pci_id_match_iterator_create(NULL);
			if (!pci_iter) {
				errout("[ERROR]: Cannot create PCI iterator");
				goto err_pci;
			}

			/* Find the matching PCI device */
			do {
				asic->pci.pdevice = pci_device_next(pci_iter);

				/* If specific PCI address provided, search for exact match */
				if (options->pci.domain || options->pci.bus || options->pci.slot || options->pci.func) {
					while (asic->pci.pdevice && (
						options->pci.domain != asic->pci.pdevice->domain ||
						options->pci.bus != asic->pci.pdevice->bus ||
						options->pci.slot != asic->pci.pdevice->dev ||
						options->pci.func != asic->pci.pdevice->func)) {
						asic->pci.pdevice = pci_device_next(pci_iter);
					}

					/*
					 * Mark that we found an exact PCI bus/slot match.
					 * This is important for NPI (No Port IO) use cases where
					 * device names may not be available for matching.
					 */
					if (asic->pci.pdevice)
						busmatch = 1;
				}
			} while (asic->pci.pdevice && !(busmatch || (asic->pci.pdevice->vendor_id == 0x1002 && is_did_match(asic, asic->pci.pdevice->device_id))));

			if (!asic->pci.pdevice) {
				errout("[ERROR]: Could not find ASIC with DID of %04lx\n", (unsigned long)asic->did);
				goto err_pci;
			}
			pci_iterator_destroy(pci_iter);

			/* Enable PCI device if kernel driver is not present */
			if (asic->options.no_kernel)
				pci_device_enable(asic->pci.pdevice);

			/* Probe PCI device to read BARs and other properties */
			pci_device_probe(asic->pci.pdevice);

			/*
			 * Determine which PCI BAR region contains MMIO registers.
			 * Start with invalid region 6 as sentinel value.
			 */
			use_region = 6;

			/* Try family-specific region detection first */
			if (asic->family <= FAMILY_SI) {
				/* Southern Islands (SI) and older typically use region 2 */
				if (asic->pci.pdevice->regions[2].is_64 == 0 &&
					asic->pci.pdevice->regions[2].is_prefetchable == 0 &&
					asic->pci.pdevice->regions[2].is_IO == 0) {
						use_region = 2;
				}
			} else if (asic->family <= FAMILY_VI) {
				/* Sea Islands (CIK) through Volcanic Islands (VI) use region 5 */
				if (asic->pci.pdevice->regions[5].is_64 == 0 &&
					asic->pci.pdevice->regions[5].is_prefetchable == 0 &&
					asic->pci.pdevice->regions[5].is_IO == 0) {
						use_region = 5;
				}
			}

			/*
			 * If family-specific detection failed, manually scan for MMIO region.
			 * Look for a BAR that is:
			 *  - Between 256KB and 4MB in size
			 *  - 32-bit addressable (not 64-bit, flag 1)
			 *  - Not prefetchable (flag 8)
			 *  - Not I/O space (flag 4)
			 *
			 * We manually scan sysfs because many distributions ship with
			 * buggy versions of libpciaccess that misreport BAR properties.
			 */
			if (use_region == 6) {
				uint64_t lowaddr, highaddr, size, flags;
				char linebuf[512];
				FILE *res;

				/* Open PCI resource file in sysfs */
				sprintf(linebuf, "/sys/bus/pci/devices/%04"PRIx32":%02"PRIx32":%02"PRIx32".%d/resource",
					(uint32_t)asic->pci.pdevice->domain,
					(uint32_t)asic->pci.pdevice->bus,
					(uint32_t)asic->pci.pdevice->dev,
					(int)asic->pci.pdevice->func);
				res = fopen(linebuf, "r");
				if (res) {
					use_region = 0;
					/* Parse each BAR entry */
					while (fgets(linebuf, sizeof linebuf, res)) {
						sscanf(linebuf, "0x%"PRIx64" 0x%"PRIx64" 0x%"PRIx64, &lowaddr, &highaddr, &flags);
						size = highaddr - lowaddr + 1;
						/* Check if this BAR matches MMIO register region criteria */
						if (size >= (256 * 1024ULL) && size <= (4096 * 1024ULL) && !(flags & (1|4|8)))
							break;
						++use_region;
					}
					fclose(res);
				}
			}

			/* Verify we found a valid MMIO region */
			if (use_region >= 6) {
				errout("[ERROR]: Could not find PCI region (debugfs mode might still work)\n");
				goto err_pci;
			}
			asic->pci.region = use_region;

			/* Map the MMIO register region into user space */
			pci_region_addr = asic->pci.pdevice->regions[use_region].base_addr;
			if (pci_device_map_range(asic->pci.pdevice, pci_region_addr,
			                         asic->pci.pdevice->regions[use_region].size,
			                         PCI_DEV_MAP_FLAG_WRITABLE, &pcimem_v)) {
				errout("[ERROR]: Could not map PCI memory\n");
				goto err_pci;
			}
			asic->pci.mem = pcimem_v;
		}
	}

	/* Scan gca configuration if needed */
	if (asic && need_config_scan)
		umr_scan_config(asic, 0);

	return asic;

err_pci:
	/* Cleanup on PCI initialization failure */
	umr_close_asic(asic);
	return NULL;
}

