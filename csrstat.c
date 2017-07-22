/*
 * Created: 23 August 2015
 * Name...: csrstat.c
 * Author.: Pike R. Alpha
 * Purpose: Command line tool for El Capitan and greater to get the active SIP status.
 *
 * Compile with: cc csrstat.c -o csrstat
 *
 * Updates:
 *      - Use csr_check so that csr_allow_all/internal are taken into account (Pike R. Alpha September 2015).
 *      - Added macOS Sierra 10.12 compatibilty (Pike R. Alpha July 2016).
 *      - Added macOS High Sierra 10.13 compatibilty (Pike R. Alpha June 2017).
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

/* Rootless configuration flags */
#define CSR_ALLOW_UNTRUSTED_KEXTS       (1 << 0)  // 1
#define CSR_ALLOW_UNRESTRICTED_FS       (1 << 1)  // 2
#define CSR_ALLOW_TASK_FOR_PID          (1 << 2)  // 4
#define CSR_ALLOW_KERNEL_DEBUGGER       (1 << 3)  // 8
#define CSR_ALLOW_APPLE_INTERNAL        (1 << 4)  // 16
#define CSR_ALLOW_UNRESTRICTED_DTRACE   (1 << 5)  // 32
#define CSR_ALLOW_UNRESTRICTED_NVRAM    (1 << 6)  // 64
#define CSR_ALLOW_DEVICE_CONFIGURATION  (1 << 7)  // 128
#define CSR_ALLOW_ANY_RECOVERY_OS       (1 << 8)  // 256
//#define CSR_ALLOW_APPLE_INTERNAL_HS     (1 << 9)  // 512 - rename me after High Sierra hss been released :-)
                                                    // cpwn: still a myth

#define CSR_VALID_FLAGS ( \
          CSR_ALLOW_UNTRUSTED_KEXTS | \
          CSR_ALLOW_UNRESTRICTED_FS | \
          CSR_ALLOW_TASK_FOR_PID | \
          CSR_ALLOW_KERNEL_DEBUGGER | \
          CSR_ALLOW_APPLE_INTERNAL | \
          CSR_ALLOW_UNRESTRICTED_DTRACE | \
          CSR_ALLOW_UNRESTRICTED_NVRAM  | \
          CSR_ALLOW_DEVICE_CONFIGURATION | \
          CSR_ALLOW_ANY_RECOVERY_OS /*\ | \
          CSR_ALLOW_APPLE_INTERNAL_HS */ \
        )

/* Syscalls */
typedef uint32_t  csr_config_t;

extern int csr_check (csr_config_t mask);
extern int csr_get_active_config (csr_config_t *config);

//==============================================================================

char *
_csr_check (
  csr_config_t  aMask
) {
  return (csr_check (aMask) != 0) ? "enabled" : "disabled";
}

//==============================================================================

int
main (
        int   argc,
  const char  *argv[]
) {
  bool      custom = 0, internal = 0;
  char      *status;
  uint32_t  config = 0;
  int       statcfg;

  statcfg = csr_get_active_config (&config); // Syscall
  if (statcfg != 0) {
    printf("Error while getting current active config (%d).\n", statcfg);
    exit(-1);
  }

  //
  // Note: Apple is no longer using 0x67 but 0x77 for csrutil disabled!!!
  //
  // cpwn: 0x0, 0x10 (CSR_ALLOW_APPLE_INTERNAL), 0x67, 0x77 & CSR_VALID_FLAGS are still magic.
  //

  /*
    csrutil:

    if (csrActiveConfig <= 0x66) {
      if (csrActiveConfig != 0x0) {
        if (csrActiveConfig == 0x10) { // == CSR_ALLOW_APPLE_INTERNAL
          str = "enabled (Apple Internal).";
        }
        else {
          // custom block
          // ...
          internstats = "disabled";
          if ((csrActiveConfig & 0x10) != 0x0) { // with CSR_ALLOW_APPLE_INTERNAL
            internstats = "enabled";
          }
          // ...
          stats = printf("\tApple Internal: %s\n", internstats);
          // ...
          warn = "\nThis is an unsupported configuration, likely to break in the future and leave your machine in an unknown state.";
        }
      }
      else { // == 0x0
        str = "enabled.";
      }
    }
    else { // > 0x66
      if (csrActiveConfig != 0x67) {
        if (csrActiveConfig == 0x77) { // with CSR_ALLOW_APPLE_INTERNAL
          str = "disabled (Apple Internal).";
        }
        else {
          // identical to custom block
        }
      }
      else { // == 0x67
        str = "disabled.";
      }
    }
  */

  /*
    aFlipflag are still unknown. While in csr_check routine check:

      1. If mask to check == CSR_ALLOW_DEVICE_CONFIGURATION, need booter->flags +kBootArgsFlagCSRConfigMode or return 1.
      2. If csr_allow_all (need booter->flags +kBootArgsFlagCSRBoot) return 0.
      3. If csr_get_active_config failed return error code.
      4. If config with mask return 0.

      ** To get config with custom csrActiveConfig need booter->flags +kBootArgsFlagCSRActiveConfig or config will = 0.
      ** Return val: 0 = success, or error otherwise.
  */

  //config = 0x40;

  switch (config) {
    case 0x0:
      status = "enable";
      break;

    case 0x67:
      status = "disabled";
      break;

    case CSR_VALID_FLAGS:
      custom = 1;
      status = "disabled (Custom Configuration)";
      break;

    case CSR_ALLOW_APPLE_INTERNAL: //0x10
      internal = 1;
      status = "enabled (Apple Internal)";
      break;

    case 0x77:
      internal = 1;
      status = "disabled (Apple Internal)";
      break;

    default:
      internal = ((config & CSR_ALLOW_APPLE_INTERNAL) != 0) ? 1 : 0;
      custom = 1;
      status = "enabled (Custom Configuration)";
  }

  printf ("System Integrity Protection status: %s.\n\n", status);

  printf ("Configuration: (0x%08x)\n", config);

  printf ("\tApple Internal...........: %s\n", internal ? "enabled" : "disabled");
  printf ("\tKext Signing Restrictions: %s\n", _csr_check(CSR_ALLOW_UNTRUSTED_KEXTS));
  printf ("\tTask for PID Restrictions: %s\n", _csr_check(CSR_ALLOW_TASK_FOR_PID));
  printf ("\tFilesystem Protections...: %s\n", _csr_check(CSR_ALLOW_UNRESTRICTED_FS));
  printf ("\tDebugging Restrictions...: %s\n", _csr_check(CSR_ALLOW_KERNEL_DEBUGGER));
  printf ("\tDTrace Restrictions......: %s\n", _csr_check(CSR_ALLOW_UNRESTRICTED_DTRACE));
  printf ("\tNVRAM Protections........: %s\n", _csr_check(CSR_ALLOW_UNRESTRICTED_NVRAM));
  printf ("\tDevice Configuration.....: %s\n", _csr_check(CSR_ALLOW_DEVICE_CONFIGURATION));
  printf ("\tBaseSystem Verification..: %s\n", _csr_check(CSR_ALLOW_ANY_RECOVERY_OS));
  //printf ("\tApple Internal HS........: %s\n", _csr_check(CSR_ALLOW_APPLE_INTERNAL_HS));

  if (custom) {
    printf("\nThis is an unsupported configuration, likely to break in the future and leave your machine in an unknown state.\n");
  }

  exit(-1);
}
