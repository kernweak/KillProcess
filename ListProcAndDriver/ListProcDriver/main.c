#include <ntddk.h>
#include <ntimage.h>
#include <ntdef.h>
#include "Ioctlcmd.h"

const WCHAR deviceLinkBuffer[]  = L"\\DosDevices\\KillProc";
const WCHAR deviceNameBuffer[]  = L"\\Device\\KillProc";

typedef NTSTATUS (*NTQUERYSYSTEMINFORMATION)(
		
		IN ULONG                        SystemInformationClass,
		OUT PVOID                        SystemInformation,
		IN ULONG                        SystemInformationLength,
		OUT PULONG                        ReturnLength OPTIONAL  );
typedef unsigned long DWORD;	
NTQUERYSYSTEMINFORMATION NtQuerySystemInformation;
#define	SystemModuleInformation	11	
typedef struct _SYSTEM_MODULE_INFORMATION
{
		ULONG  Reserved[2];
		PVOID  Base;
		ULONG  Size;
		ULONG  Flags;
		USHORT Index;
		USHORT Unknown;
		USHORT LoadCount;
		USHORT ModuleNameOffset;
		CHAR   ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

PDEVICE_OBJECT g_HookDevice;
NTSTATUS  PsLookupProcessByProcessId(ULONG ProcessId,PEPROCESS *Process);

typedef  NTSTATUS  (*PSPTERPROC) ( PEPROCESS Process, NTSTATUS ExitStatus );
PSPTERPROC MyPspTerminateProcess = NULL ;


NTSTATUS OnUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING          deviceLinkUnicodeString;
	PDEVICE_OBJECT	   p_NextObj;


	DbgPrint("OnUnload called\n");

	p_NextObj = DriverObject->DeviceObject;

	if (p_NextObj != NULL)
	{

		RtlInitUnicodeString( &deviceLinkUnicodeString, deviceLinkBuffer );
		IoDeleteSymbolicLink( &deviceLinkUnicodeString );

		IoDeleteDevice( DriverObject->DeviceObject );
	}
	return STATUS_SUCCESS;
}

NTSTATUS 
DispatchControl(
    IN PDEVICE_OBJECT DeviceObject, 
    IN PIRP Irp)
{
    PIO_STACK_LOCATION      irpStack;
    PVOID                   inputBuffer;
    PVOID                   outputBuffer;
    PVOID			     userBuffer;
    ULONG                   inputBufferLength;
    ULONG                   outputBufferLength;
    ULONG                   ioControlCode;
    NTSTATUS		     ntstatus;

    unsigned int i;

    unsigned total = 0;
    ULONG count = 0;

    HANDLE handle;


    ULONG cnt;

    PEPROCESS Eprocess = NULL;
    DWORD pid;


    ntstatus = Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    irpStack = IoGetCurrentIrpStackLocation (Irp);

    inputBuffer             = Irp->AssociatedIrp.SystemBuffer;
    inputBufferLength       = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    outputBuffer            = Irp->AssociatedIrp.SystemBuffer;
    outputBufferLength      = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
    ioControlCode           = irpStack->Parameters.DeviceIoControl.IoControlCode;

    
    
    switch (irpStack->MajorFunction)
   {
    case IRP_MJ_CREATE:
        break;

    case IRP_MJ_SHUTDOWN:
        break;

    case IRP_MJ_CLOSE:
        break;

    case IRP_MJ_DEVICE_CONTROL:

        if(IOCTL_TRANSFER_TYPE(ioControlCode) == METHOD_NEITHER) 
	{
            outputBuffer = Irp->UserBuffer;
        }

        
	switch (ioControlCode ) 
	{

	case IOCTL_PROC_KILL:
				if(MyPspTerminateProcess==NULL)
				{
					*(DWORD*)outputBuffer = -1;
					Irp->IoStatus.Information = sizeof(DWORD);
				}
				else
				{
					pid = *(DWORD*)inputBuffer;
					{
						
						ntstatus = PsLookupProcessByProcessId(pid , &Eprocess);//ObDereference
						if(!NT_SUCCESS(ntstatus))
						{
							DbgPrint("Failed to lookup process 0x%x, status %8.8x\n", pid , ntstatus);
							*(DWORD*)outputBuffer = 1;
							Irp->IoStatus.Information = sizeof(DWORD);
							break;
						}
						DbgPrint("Lookup of process 0x%x, PEPROCESS at %8.8x\n", pid, Eprocess);
						ntstatus = MyPspTerminateProcess(Eprocess, 0);
						if(!NT_SUCCESS(ntstatus))
						{
							DbgPrint("Failed to terminate process 0x%x, status %8.8x\n", pid, ntstatus);
							*(DWORD*)outputBuffer = 2;
							Irp->IoStatus.Information = sizeof(DWORD);
							break;
						}
						*(DWORD*)outputBuffer = 0;
						Irp->IoStatus.Information = sizeof(DWORD);
						DbgPrint("Process 0x%x terminated\n", pid);
					}
				}
				break;
					
      
	default:
			break;
    	}
    IoCompleteRequest( Irp, IO_NO_INCREMENT );
     
    }
    return ntstatus;  
}

NTSTATUS DispatchCreate (
		IN PDEVICE_OBJECT	pDevObj,
		IN PIRP		pIrp)
{

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest( pIrp, IO_NO_INCREMENT );
	return STATUS_SUCCESS;
}

ULONG GetFunctionAddr( IN PCWSTR FunctionName)
	{
		UNICODE_STRING UniCodeFunctionName;
		
		RtlInitUnicodeString( &UniCodeFunctionName, FunctionName );
		return (ULONG)MmGetSystemRoutineAddress( &UniCodeFunctionName );    
		
	}

VOID DoFind(IN PVOID pContext)
	{
		NTSTATUS ret;
		PSYSTEM_MODULE_INFORMATION  module = NULL;
		ULONG n=0;
		void  *buf    = NULL;
		ULONG ntosknlBase;
		ULONG ntosknlEndAddr;
		ULONG curAddr;
		ULONG code1_sp3=0x8b55ff8b,code2_sp3=0xA16456EC,code3_sp3=0x00000124,code4_sp3=0x3B08758B;
		ULONG i;
		
		NtQuerySystemInformation=(NTQUERYSYSTEMINFORMATION)GetFunctionAddr(L"NtQuerySystemInformation");
		if (!NtQuerySystemInformation) 
		{
			DbgPrint("Find NtQuerySystemInformation faild!");
			goto Ret;
		}
		ret=NtQuerySystemInformation(SystemModuleInformation,&n,0,&n);
		if (NULL==( buf=ExAllocatePoolWithTag(NonPagedPool, n, 'DFSP')))
		{
			DbgPrint("ExAllocatePool() failed\n" );
			goto Ret;
		}
		ret=NtQuerySystemInformation(SystemModuleInformation,buf,n,NULL);
		if (!NT_SUCCESS(ret))	{
			DbgPrint("NtQuerySystemInformation faild!");
			goto Ret;
		} 
		//+1 reason: The data returned to the SystemInformation buffer is a ULONG count of the number of
		//modules followed immediately by an array of SYSTEM_MODULE_INFORMATION
		module=(PSYSTEM_MODULE_INFORMATION)((PULONG)buf+1);
		ntosknlEndAddr=(ULONG)module->Base+(ULONG)module->Size;
		ntosknlBase=(ULONG)module->Base;
		curAddr=ntosknlBase;
		ExFreePool(buf);
		//MmIsAddressValid(i)
		for (i=curAddr;i<=ntosknlEndAddr;i++)
		{
				if (*((ULONG *)i)==code1_sp3) 
				{
					if (*((ULONG *)(i+4))==code2_sp3) 
					{
						if (*((ULONG *)(i+8))==code3_sp3) 
						{
							if (*((ULONG *)(i+12))==code4_sp3) 
							{
								MyPspTerminateProcess=(PSPTERPROC)i;
								break;
							}
						}
					}
				}
		}
Ret:
	PsTerminateSystemThread(STATUS_SUCCESS);
	}

VOID GetPspAddr()
{
		HANDLE hThread;
		PVOID objtowait=0;
		NTSTATUS dwStatus = 
			PsCreateSystemThread(
			&hThread,
	              0,
		       NULL,
			(HANDLE)0,
	              NULL,
		       DoFind,
			NULL
			);
		NTSTATUS st;
		if ((KeGetCurrentIrql())!=PASSIVE_LEVEL)
		{
			st=KfRaiseIrql(PASSIVE_LEVEL);//KeLowerIrql()?
		
		}
		if ((KeGetCurrentIrql())!=PASSIVE_LEVEL)
		{
			
			return;
		}
		
		ObReferenceObjectByHandle(
			hThread,
			THREAD_ALL_ACCESS,
			NULL,
			KernelMode,
			&objtowait,
			NULL
			); 

		st=KeWaitForSingleObject(objtowait,Executive,KernelMode,FALSE,NULL); //NULL表示无限期等待.
		return;
	
	
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS rc;
	
	RTL_OSVERSIONINFOW osvi;
	NTSTATUS                ntStatus;
	UNICODE_STRING          deviceNameUnicodeString;
       UNICODE_STRING          deviceLinkUnicodeString;   

	RtlInitUnicodeString (&deviceNameUnicodeString,
	    deviceNameBuffer );
	RtlInitUnicodeString (&deviceLinkUnicodeString,
	    deviceLinkBuffer );

	ntStatus = IoCreateDevice ( DriverObject,
	    0,
	    &deviceNameUnicodeString,
	    FILE_DEVICE_SWAP,
	    0,
	    TRUE,
	    &g_HookDevice );

	if(! NT_SUCCESS(ntStatus))
	{
	      DbgPrint(("Failed to create device!\n"));
	      return ntStatus;
	 }		
	ntStatus = IoCreateSymbolicLink (&deviceLinkUnicodeString,
	    &deviceNameUnicodeString );
	if(! NT_SUCCESS(ntStatus)) 
	{
		 IoDeleteDevice(DriverObject->DeviceObject);
	        DbgPrint("Failed to create symbolic link!\n");
	        return ntStatus;
	 }
        DriverObject->MajorFunction[IRP_MJ_SHUTDOWN]        =
        DriverObject->MajorFunction[IRP_MJ_CREATE]          =   DispatchCreate;
        DriverObject->MajorFunction[IRP_MJ_CLOSE]           =    
	 DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = DispatchControl;

	DriverObject->DriverUnload  = OnUnload;

	GetPspAddr();
	if(MyPspTerminateProcess == NULL)
	{
		DbgPrint("PspFunc Not Find!\n");
	}
	return STATUS_SUCCESS;
}
