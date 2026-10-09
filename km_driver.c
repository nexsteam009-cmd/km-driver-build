// km_driver.c — Kernel driver đọc/ghi memory process khác
// Build: GitHub Actions + WDK

#include <ntddk.h>

// ── Kernel API prototypes ───────────────────────────────────────────
NTKERNELAPI PEPROCESS NTAPI PsGetProcessPeb(_In_ PEPROCESS Process);
NTKERNELAPI NTSTATUS  NTAPI PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS *Process);
NTKERNELAPI PCHAR     NTAPI PsGetProcessImageFileName(_In_ PEPROCESS Process);

// ── Manual PEB / LDR structures ─────────────────────────────────────
typedef struct _MY_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} MY_UNICODE_STRING, *PMY_UNICODE_STRING;

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    MY_UNICODE_STRING FullDllName;
    MY_UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

typedef struct _MY_PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

typedef struct _MY_PEB {
    BYTE              Reserved1[2];
    BYTE              BeingDebugged;
    BYTE              Reserved2[1];
    PVOID             Reserved3[2];
    PMY_PEB_LDR_DATA  Ldr;
    PVOID             ProcessParameters;
} MY_PEB, *PMY_PEB;

#define DEVICE_NAME     L"\\Device\\PubgExtKM"
#define SYMLINK_NAME    L"\\DosDevices\\PubgExtKM"

// ── IOCTL codes ─────────────────────────────────────────────────────
#define IOCTL_READ_MEMORY       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_PID           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_BASE_ADDR     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ── Request structs ─────────────────────────────────────────────────
typedef struct _MEMORY_REQUEST {
    ULONG     ProcessId;
    ULONG     _pad;
    ULONGLONG Address;
    ULONGLONG Buffer;
    ULONGLONG Size;
} MEMORY_REQUEST, *PMEMORY_REQUEST;

typedef struct _BASE_ADDR_REQUEST {
    ULONG     ProcessId;
    ULONG     _pad;
    ULONGLONG ModuleBase;
    ULONGLONG ModuleSize;
    WCHAR     ModuleName[64];
} BASE_ADDR_REQUEST, *PBASE_ADDR_REQUEST;

typedef struct _GET_PID_REQUEST {
    WCHAR     ProcessName[64];
    ULONG     ProcessId;
} GET_PID_REQUEST, *PGET_PID_REQUEST;

// ── Đọc memory process ──────────────────────────────────────────────
static NTSTATUS ReadProcessMemory(
    ULONG ProcessId,
    ULONGLONG Address,
    PVOID Buffer,
    ULONGLONG Size,
    PULONGLONG BytesRead)
{
    PEPROCESS Process = NULL;
    KAPC_STATE ApcState;
    NTSTATUS Status;
    BOOLEAN Attached = FALSE;

    if (!Buffer || !Size || Size > 0x10000000) return STATUS_INVALID_PARAMETER;

    Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &Process);
    if (!NT_SUCCESS(Status)) return Status;

    __try {
        KeStackAttachProcess(Process, &ApcState);
        Attached = TRUE;

        ProbeForRead((PVOID)(ULONG_PTR)Address, (SIZE_T)Size, 1);
        RtlCopyMemory(Buffer, (PVOID)(ULONG_PTR)Address, (SIZE_T)Size);
        if (BytesRead) *BytesRead = Size;

        KeUnstackDetachProcess(&ApcState);
        Attached = FALSE;
        Status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (Attached) KeUnstackDetachProcess(&ApcState);
        Status = GetExceptionCode();
    }

    ObDereferenceObject(Process);
    return Status;
}

// ── Ghi memory process ──────────────────────────────────────────────
static NTSTATUS WriteProcessMemory(
    ULONG ProcessId,
    ULONGLONG Address,
    PVOID Buffer,
    ULONGLONG Size,
    PULONGLONG BytesWritten)
{
    PEPROCESS Process = NULL;
    KAPC_STATE ApcState;
    NTSTATUS Status;
    BOOLEAN Attached = FALSE;

    if (!Buffer || !Size || Size > 0x10000000) return STATUS_INVALID_PARAMETER;

    Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &Process);
    if (!NT_SUCCESS(Status)) return Status;

    __try {
        KeStackAttachProcess(Process, &ApcState);
        Attached = TRUE;

        ProbeForWrite((PVOID)(ULONG_PTR)Address, (SIZE_T)Size, 1);
        RtlCopyMemory((PVOID)(ULONG_PTR)Address, Buffer, (SIZE_T)Size);
        if (BytesWritten) *BytesWritten = Size;

        KeUnstackDetachProcess(&ApcState);
        Attached = FALSE;
        Status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (Attached) KeUnstackDetachProcess(&ApcState);
        Status = GetExceptionCode();
    }

    ObDereferenceObject(Process);
    return Status;
}

// ── So sánh chuỗi ───────────────────────────────────────────────────
static BOOLEAN StrEqIA(const char* a, const char* b)
{
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return FALSE;
        a++; b++;
    }
    return (*a == 0 && *b == 0);
}

// ── Lấy PID theo tên ────────────────────────────────────────────────
static NTSTATUS GetProcessIdByName(const WCHAR* WideName, PULONG OutPid)
{
    char targetAscii[64] = { 0 };
    for (int i = 0; i < 63 && WideName[i]; i++) {
        targetAscii[i] = (char)(WideName[i] & 0xFF);
    }

    BOOLEAN found = FALSE;
    ULONG   foundPid = 0;

    for (ULONG pid = 4; pid < 0x10000; pid += 4) {
        PEPROCESS Process = NULL;
        NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &Process);
        if (!NT_SUCCESS(Status)) continue;

        PCHAR imageName = PsGetProcessImageFileName(Process);
        if (imageName && StrEqIA(imageName, targetAscii)) {
            foundPid = pid;
            found = TRUE;
        }
        ObDereferenceObject(Process);
        if (found) break;
    }

    if (found) {
        *OutPid = foundPid;
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_FOUND;
}

// ── Lấy base module ─────────────────────────────────────────────────
static NTSTATUS GetModuleBase(
    ULONG ProcessId,
    const WCHAR* ModuleName,
    PULONGLONG OutBase,
    PULONGLONG OutSize)
{
    PEPROCESS Process = NULL;
    KAPC_STATE ApcState;
    NTSTATUS Status;
    BOOLEAN Attached = FALSE;

    Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &Process);
    if (!NT_SUCCESS(Status)) return Status;

    __try {
        KeStackAttachProcess(Process, &ApcState);
        Attached = TRUE;

        PMY_PEB Peb = (PMY_PEB)PsGetProcessPeb(Process);
        if (!Peb || !Peb->Ldr) {
            Status = STATUS_NOT_FOUND;
            __leave;
        }

        PLIST_ENTRY head = &Peb->Ldr->InLoadOrderModuleList;
        PLIST_ENTRY entry = head->Flink;

        BOOLEAN found = FALSE;
        while (entry != head) {
            PMY_LDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(
                entry, MY_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            if (mod->BaseDllName.Buffer) {
                BOOLEAN match = TRUE;
                USHORT len = mod->BaseDllName.Length / sizeof(WCHAR);
                for (USHORT i = 0; i < len && ModuleName[i]; i++) {
                    WCHAR a = mod->BaseDllName.Buffer[i];
                    WCHAR b = ModuleName[i];
                    if (a >= L'A' && a <= L'Z') a += 32;
                    if (b >= L'A' && b <= L'Z') b += 32;
                    if (a != b) { match = FALSE; break; }
                }
                if (match) {
                    *OutBase = (ULONGLONG)mod->DllBase;
                    *OutSize = (ULONGLONG)mod->SizeOfImage;
                    found = TRUE;
                    break;
                }
            }
            entry = entry->Flink;
        }

        Status = found ? STATUS_SUCCESS : STATUS_NOT_FOUND;

        KeUnstackDetachProcess(&ApcState);
        Attached = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (Attached) KeUnstackDetachProcess(&ApcState);
        Status = GetExceptionCode();
    }

    ObDereferenceObject(Process);
    return Status;
}

// ── IOCTL dispatcher ────────────────────────────────────────────────
static NTSTATUS DispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG ReturnLength = 0;

    ULONG IoControlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID InputBuffer   = Irp->AssociatedIrp.SystemBuffer;
    ULONG InputLength   = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG OutputLength  = stack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (IoControlCode) {

    case IOCTL_READ_MEMORY: {
        if (InputLength >= sizeof(MEMORY_REQUEST) && InputBuffer) {
            PMEMORY_REQUEST req = (PMEMORY_REQUEST)InputBuffer;
            ULONGLONG bytesRead = 0;
            Status = ReadProcessMemory(req->ProcessId, req->Address,
                                        (PVOID)req->Buffer, req->Size, &bytesRead);
            ReturnLength = (ULONG)bytesRead;
        } else {
            Status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_WRITE_MEMORY: {
        if (InputLength >= sizeof(MEMORY_REQUEST) && InputBuffer) {
            PMEMORY_REQUEST req = (PMEMORY_REQUEST)InputBuffer;
            ULONGLONG bytesWritten = 0;
            Status = WriteProcessMemory(req->ProcessId, req->Address,
                                         (PVOID)req->Buffer, req->Size, &bytesWritten);
            ReturnLength = (ULONG)bytesWritten;
        } else {
            Status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_GET_PID: {
        if (InputLength >= sizeof(GET_PID_REQUEST) &&
            OutputLength >= sizeof(GET_PID_REQUEST) &&
            InputBuffer) {
            PGET_PID_REQUEST req = (PGET_PID_REQUEST)InputBuffer;
            ULONG pid = 0;
            Status = GetProcessIdByName(req->ProcessName, &pid);
            if (NT_SUCCESS(Status)) {
                req->ProcessId = pid;
                ReturnLength = sizeof(GET_PID_REQUEST);
            }
        } else {
            Status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_GET_BASE_ADDR: {
        if (InputLength >= sizeof(BASE_ADDR_REQUEST) &&
            OutputLength >= sizeof(BASE_ADDR_REQUEST) &&
            InputBuffer) {
            PBASE_ADDR_REQUEST req = (PBASE_ADDR_REQUEST)InputBuffer;
            ULONGLONG base = 0, size = 0;
            Status = GetModuleBase(req->ProcessId, req->ModuleName, &base, &size);
            if (NT_SUCCESS(Status)) {
                req->ModuleBase = base;
                req->ModuleSize = size;
                ReturnLength = sizeof(BASE_ADDR_REQUEST);
            }
        } else {
            Status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    default:
        break;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = ReturnLength;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

// ── Create / Close ──────────────────────────────────────────────────
static NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// ── DriverUnload ────────────────────────────────────────────────────
static VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symlink;
    RtlInitUnicodeString(&symlink, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlink);

    if (DriverObject->DeviceObject)
        IoDeleteDevice(DriverObject->DeviceObject);

    DbgPrint("[PubgExtKM] Driver unloaded.\n");
}

// ── DriverEntry ─────────────────────────────────────────────────────
NTSTATUS DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS        Status;
    UNICODE_STRING  DeviceName;
    UNICODE_STRING  SymlinkName;
    PDEVICE_OBJECT  DeviceObject = NULL;

    RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
    RtlInitUnicodeString(&SymlinkName, SYMLINK_NAME);

    Status = IoCreateDevice(DriverObject, 0, &DeviceName,
                            FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
                            FALSE, &DeviceObject);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("[PubgExtKM] IoCreateDevice failed: 0x%08X\n", Status);
        return Status;
    }

    Status = IoCreateSymbolicLink(&SymlinkName, &DeviceName);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("[PubgExtKM] IoCreateSymbolicLink failed: 0x%08X\n", Status);
        IoDeleteDevice(DeviceObject);
        return Status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
    DriverObject->DriverUnload                          = DriverUnload;

    DbgPrint("[PubgExtKM] Driver loaded. Device: %ws\n", DEVICE_NAME);

    return STATUS_SUCCESS;
}
