#pragma warning (disable : 4100)
#include "Driver.h"

typedef struct _SYSTEM_THREADS {
	// https://doxygen.reactos.org/d5/d9e/struct__SYSTEM__THREADS.html
	LARGE_INTEGER  KernelTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  CreateTime;
	ULONG          WaitTime;
	PVOID          StartAddress;
	CLIENT_ID      ClientId;
	KPRIORITY      Priority;
	KPRIORITY      BasePriority;
	ULONG          ContextSwitchCount;
	LONG           ThreadState;
	LONG           WaitReason;
} SYSTEM_THREADS, * PSYSTEM_THREADS;


typedef struct _SYSTEM_PROCESSES {
	// https://doxygen.reactos.org/d6/dfd/struct__SYSTEM__PROCESSES.html
	ULONG            NextEntryOffset;
	ULONG            NumberOfThreads;
	ULONG            Reserved1[6];
	LARGE_INTEGER    CreateTime;
	LARGE_INTEGER    UserTime;
	LARGE_INTEGER    KernelTime;
	UNICODE_STRING   ImageName;
	KPRIORITY        BasePriority;
	SIZE_T           UniqueProcessId;
	SIZE_T           InheritedFromUniqueProcessId;
	ULONG            HandleCount;
	ULONG            Reserved2[2];
	VM_COUNTERS      VmCounters;
	IO_COUNTERS      IoCounters;
	SYSTEM_THREADS   Threads[1];
} SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;

#define SystemProcessInformation 5

#define POOL_TAG 'enoN' //endian byte ordering

NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

char ForbiddenDrivers[41][50] = {
	"Dbgv.sys",
	"PROCMON23.sys",
	"dbk32.sys",
	"dbk64.sys",
	"windowskernelexplorer.sys",
	"ksdumperdriver.sys",
	"capcom.sys",
	"iqvw64e.sys",
	"iqvw32.sys",
	"adv64drv.sys",
	"agent64.sys",
	"alsysio64.sys",
	"amifldrv64.sys",
	"asio.sys",
	"asrautochkupddrv.sys",
	"asrdrv10.sys",
	"asrdrv101.sys",
	"asribdrv.sys",
	"asromgdrv.sys",
	"asrrapidstartdrv.sys",
	"asrsmartconnectdrv.sys",
	"asupio.sys",
	"atillk64.sys",
	"bs_def64.sys",
	"asupio.sys",
	"atillk64.sys",
	"citmdrv_amd64.sys",
	"citmdrv_ia64.sys",
	"cpuz_x64.sys",
	"glckio2.sys",
	"inpoutx64.sys",
	"kprocesshacker.sys",
	"rzpnk.sys",
	"v0edkxsuivz.sys",
	"gdrv.sys",
	"driver.sys",
	"pchunter",
	"macromap",
	"kdmapper",
	"blekbon",
	"blackbone"
};

char ForbiddenModules[15][30] = {
	"Dumper.dll",
	"Glob.dll",
	"mswsock.dll",
	"perl512.dll",
	"vmclinetcore.dll",
	"wmwareui.dll",
	"virtualbox.dll",
	"qtcorevbox4.dll",
	"netredirect.dll",
	"atmfd.dll",
	"cdd.dll",
	"rdpdd.dll",
	"vga.dll",
	"workerdd.dll",
	"msvbvm60.dll"
};


VOID DriverScan(PVOID Context)
{
	//if ForbiddenDrivers -> KillProcess(id)
}

VOID ModuleScan(PVOID Context)
{
	//if ForbiddenModule -> KillProcess(id)
}

NTSTATUS CustomDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS ntstatus = STATUS_SUCCESS;

	UNICODE_STRING uniName = RTL_CONSTANT_STRING(L"\\SystemRoot\\KernelProcessList.txt");  //Create a log file inside Windows directory
	OBJECT_ATTRIBUTES objAttr;

	InitializeObjectAttributes(&objAttr, &uniName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	HANDLE file;
	IO_STATUS_BLOCK ioStatusBlock;

	ntstatus = ZwCreateFile(&file,
		GENERIC_WRITE,
		&objAttr, &ioStatusBlock, NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);

	if (NT_SUCCESS(ntstatus)) 
	{
		ULONG bufferSize = 0;
		if (ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize) == STATUS_INFO_LENGTH_MISMATCH)
		{
			if (bufferSize)
			{
				PVOID memory = ExAllocatePoolWithTag(PagedPool, bufferSize, POOL_TAG);

				if (memory)
				{
					ntstatus = ZwQuerySystemInformation(SystemProcessInformation, memory, bufferSize, &bufferSize);
					if (NT_SUCCESS(ntstatus))
					{
						PSYSTEM_PROCESSES processEntry = static_cast<PSYSTEM_PROCESSES>(memory);

						do
						{
							if (processEntry->ImageName.Length)
							{
								CHAR string[100];
								ntstatus = RtlStringCbPrintfA(string, _countof(string), "%ws : %llu\n", processEntry->ImageName.Buffer, processEntry->UniqueProcessId);

								if (NT_SUCCESS(ntstatus))
								{
									size_t length;
									ntstatus = RtlStringCbLengthA(string, _countof(string), &length);

									if (NT_SUCCESS(ntstatus))
									{
										ntstatus = ZwWriteFile(file, NULL, NULL, NULL, &ioStatusBlock, string, (ULONG)length, NULL, NULL);
									}
								}
							}
							processEntry = (PSYSTEM_PROCESSES)((BYTE*)processEntry + processEntry->NextEntryOffset);
						} 
						while (processEntry->NextEntryOffset);
					}
					ExFreePoolWithTag(memory, POOL_TAG);
				}
			}
		}
		ZwClose(file);
	}
	return ntstatus;
}

NTSTATUS UnloadDriver(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	
	DbgPrintEx(0, 0, "Driver UnLoaded!");
	//TODO: KillProcess

	return STATUS_SUCCESS;
}