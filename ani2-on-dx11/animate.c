/*++

Copyright (c) Microsoft Corporation. All rights reserved.

Module Name:

    animate.c

Abstract:

    Startup animation implementation.

--*/

#include <stddef.h>

#pragma code_seg("INIT")
#pragma data_seg("INIT_RW")
#pragma const_seg("INIT_RD")

// #include "ntdef.h"
#include "stdio.h"
#include "stdlib.h"
#include "wtypes.h"


// Tell linker to put startup animation code and data into INIT section
#pragma comment(linker, "/merge:INIT_RD=INIT")
#pragma comment(linker, "/merge:INIT_RW=INIT")
#pragma comment(linker, "/merge:D3D=INIT")
#pragma comment(linker, "/merge:D3D_RD=INIT")
#pragma comment(linker, "/merge:D3D_RW=INIT")
#pragma comment(linker, "/merge:XGRPH=INIT")
#pragma comment(linker, "/merge:XGRPH_RD=INIT")

// We always want to link with the animation code, so that we can
// keep the build from breaking. Thats why we use a global to
// decide whether to run the animation or not. The global tricks
// the linker into linking in all the code the animation uses.

#ifdef NOANI
BOOL gBootAnimation_DoAnimation = FALSE;
#else
BOOL gBootAnimation_DoAnimation = TRUE;
#endif

#ifdef BOOTSOUND
BOOL gBootAnimation_DoSound = TRUE;
#else
BOOL gBootAnimation_DoSound = FALSE;
#endif

// definitions ripped from src

#define DECLSPEC_RDATA

typedef CCHAR KPROCESSOR_MODE;
typedef signed char SCHAR;
typedef SCHAR* PSCHAR;
typedef UCHAR KIRQL;
typedef KIRQL* PKIRQL;
typedef short CSHORT;

typedef enum _MODE {
    KernelMode,
    MaximumMode
} MODE;

typedef enum _WAIT_TYPE {
    WaitAll,
    WaitAny,
    WaitNotification,
    WaitDequeue,
    WaitDpc
} WAIT_TYPE;

typedef PVOID(*OB_ALLOCATE_METHOD)(
    IN SIZE_T NumberOfBytes,
    IN ULONG Tag
    );

typedef VOID(*OB_FREE_METHOD)(
    IN PVOID Pointer
    );

typedef VOID(*OB_CLOSE_METHOD)(
    IN PVOID Object,
    IN ULONG SystemHandleCount
    );

typedef VOID(*OB_DELETE_METHOD)(
    IN PVOID Object
    );

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
#ifdef MIDL_PASS
    [size_is(MaximumLength), length_is(Length)]
#endif // MIDL_PASS
        _Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} STRING;

typedef STRING *PSTRING;
typedef PSTRING POBJECT_STRING;

typedef NTSTATUS(*OB_PARSE_METHOD)(
    IN PVOID ParseObject,
    IN struct _OBJECT_TYPE* ObjectType,
    IN ULONG Attributes,
    IN OUT POBJECT_STRING CompleteName,
    IN OUT POBJECT_STRING RemainingName,
    IN OUT PVOID Context OPTIONAL,
    OUT PVOID* Object
    );

typedef struct _OBJECT_TYPE {
    OB_ALLOCATE_METHOD AllocateProcedure;
    OB_FREE_METHOD FreeProcedure;
    OB_CLOSE_METHOD CloseProcedure;
    OB_DELETE_METHOD DeleteProcedure;
    OB_PARSE_METHOD ParseProcedure;
    PVOID DefaultObject;
    ULONG PoolTag;
} OBJECT_TYPE, * POBJECT_TYPE;

typedef
VOID
(*PKNORMAL_ROUTINE) (
    IN PVOID NormalContext,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2
    );

typedef
VOID
(*PKSTART_ROUTINE) (
    IN PVOID StartContext
    );

typedef
VOID
(*PKRUNDOWN_ROUTINE) (
    IN struct _KAPC* Apc
    );

PVOID
ExAllocatePoolWithTag(
    IN SIZE_T NumberOfBytes,
    IN ULONG Tag
)

#define VOID void

VOID
ExFreePool(
    IN PVOID P
)

DECLSPEC_RDATA OBJECT_TYPE PsThreadObjectType = {
    ExAllocatePoolWithTag,
    ExFreePool,
    NULL,
    NULL,
    NULL,
    (PVOID)FIELD_OFFSET(KTHREAD, Header),
    'erhT'
};

typedef
VOID
(*PKKERNEL_ROUTINE) (
    IN struct _KAPC* Apc,
    IN OUT PKNORMAL_ROUTINE* NormalRoutine,
    IN OUT PVOID* NormalContext,
    IN OUT PVOID* SystemArgument1,
    IN OUT PVOID* SystemArgument2
    );

typedef struct _KSEMAPHORE {
    DISPATCHER_HEADER Header;
    LONG Limit;
} KSEMAPHORE, * PKSEMAPHORE, * RESTRICTED_POINTER PRKSEMAPHORE;

typedef struct _KWAIT_BLOCK {
    LIST_ENTRY WaitListEntry;
    struct _KTHREAD* RESTRICTED_POINTER Thread;
    PVOID Object;
    struct _KWAIT_BLOCK* RESTRICTED_POINTER NextWaitBlock;
    USHORT WaitKey;
    USHORT WaitType;
} KWAIT_BLOCK, * PKWAIT_BLOCK, * RESTRICTED_POINTER PRKWAIT_BLOCK;

typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[MaximumMode];
    struct _KPROCESS* Process;
    BOOLEAN KernelApcInProgress;
    BOOLEAN KernelApcPending;
    BOOLEAN UserApcPending;
    BOOLEAN ApcQueueable;
} KAPC_STATE, * PKAPC_STATE, * RESTRICTED_POINTER PRKAPC_STATE;

typedef struct _KQUEUE {
    DISPATCHER_HEADER Header;
    LIST_ENTRY EntryListHead;
    ULONG CurrentCount;
    ULONG MaximumCount;
    LIST_ENTRY ThreadListHead;
} KQUEUE, * PKQUEUE, * RESTRICTED_POINTER PRKQUEUE;

typedef struct _KTIMER {
    DISPATCHER_HEADER Header;
    ULARGE_INTEGER DueTime;
    LIST_ENTRY TimerListEntry;
    struct _KDPC* Dpc;
    LONG Period;
} KTIMER, * PKTIMER, * RESTRICTED_POINTER PRKTIMER;

typedef struct _KAPC {
    CSHORT Type;
    KPROCESSOR_MODE ApcMode;
    BOOLEAN Inserted;
    struct _KTHREAD* Thread;
    LIST_ENTRY ApcListEntry;
    PKKERNEL_ROUTINE KernelRoutine;
    PKRUNDOWN_ROUTINE RundownRoutine;
    PKNORMAL_ROUTINE NormalRoutine;
    PVOID NormalContext;

    //
    // N.B. The following two members MUST be together.
    //

    PVOID SystemArgument1;
    PVOID SystemArgument2;
} KAPC, * PKAPC, * RESTRICTED_POINTER PRKAPC;

typedef struct _KTHREAD {

    //
    // The dispatcher header and mutant listhead are fairly infrequently
    // referenced, but pad the thread to a 32-byte boundary (assumption
    // that pool allocation is in units of 32-bytes).
    //

    DISPATCHER_HEADER Header;
    LIST_ENTRY MutantListHead;

    //
    // The following entries are referenced during clock interrupts.
    //

    ULONG KernelTime;

    //
    // The following fields are referenced during trap, interrupts, or
    // context switches.
    //

    PVOID StackBase;
    PVOID StackLimit;
    PVOID KernelStack;
    PVOID TlsData;
    UCHAR State;
    BOOLEAN Alerted[MaximumMode];
    BOOLEAN Alertable;
    UCHAR NpxState;
    CHAR Saturation;
    SCHAR Priority;
    UCHAR Padding;
    KAPC_STATE ApcState;
    ULONG ContextSwitches;

    //
    // The following fields are referenced during wait operations.
    //

    LONG_PTR WaitStatus;
    KIRQL WaitIrql;
    KPROCESSOR_MODE WaitMode;
    BOOLEAN WaitNext;
    UCHAR WaitReason;
    PRKWAIT_BLOCK WaitBlockList;
    LIST_ENTRY WaitListEntry;
    ULONG WaitTime;
    ULONG KernelApcDisable;
    LONG Quantum;
    SCHAR BasePriority;
    UCHAR DecrementCount;
    SCHAR PriorityDecrement;
    BOOLEAN DisableBoost;
    UCHAR NpxIrql;
    CCHAR SuspendCount;
    BOOLEAN Preempted;
    BOOLEAN HasTerminated;

    //
    // The following fields are referenced during queue operations.
    //

    PRKQUEUE Queue;
    LIST_ENTRY QueueListEntry;

    //
    // The following fields are referenced when the thread is blocking for a
    // timed interval.
    //

    KTIMER Timer;
    KWAIT_BLOCK TimerWaitBlock;

    //
    // The following fields are referenced when the thread is initialized
    // and very infrequently thereafter.
    //

    KAPC SuspendApc;
    KSEMAPHORE SuspendSemaphore;
    LIST_ENTRY ThreadListEntry;

} KTHREAD, * PKTHREAD, * RESTRICTED_POINTER PRKTHREAD;

typedef enum _KWAIT_REASON {
    Executive
} KWAIT_REASON;

typedef struct _DISPATCH_HEADER {
    UCHAR Type;
    UCHAR Absolute;
    UCHAR Size;
    UCHAR Inserted;
    LONG SignalState;
    LIST_ENTRY WaitListHead;
} DISPATCHER_HEADER;

typedef struct _KEVENT {
    DISPATCHER_HEADER Header;
} KEVENT, *PKEVENT, *RESTRICTED_POINTER PKEVENT;

typedef struct _KWAIT_BLOCK {
    LIST_ENTRY WaitListEntry;
    struct _KTHREAD *RESTRICTED_POINTER Thread;
    PVOID Object;
    struct _KWAIT_BLOCK* RESTRICTED_POINTER NextWaitBlock;
    USHORT WaitKey;
    USHORT WaitType;
} KWAIT_BLOCK, *PKWAIT_BLOCK, *RESTRICTED_POINTER PKWAIT_BLOCK;

typedef struct _ETHREAD {
    KTHREAD Tcb;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExitTime;

    union {
        NTSTATUS ExitStatus;
        PVOID OfsChain;       // needed for the nt build of the C runtime
    };
    union {
        LIST_ENTRY ReaperListEntry;
        LIST_ENTRY ActiveTimerListHead;
    };
    HANDLE UniqueThread;
    PVOID StartAddress;

    //
    // Io
    //

    LIST_ENTRY IrpList;

#ifdef DEVKIT
    //
    // Dm
    //
    // keep this at the end so kd exts don't get confused
    //

    PVOID DebugData;
#endif
} ETHREAD, * PETHREAD;

// Background animation thread.
HANDLE g_hThread;

// Entrypoing into the animation thread.
VOID AnipStartAnimationThread(PKSTART_ROUTINE StartRoutine, PVOID StartContext);

// Main animation routine as defined in the animation library.
VOID AnipRunAnimation();

#define CONTIGUOUS_BLOCK_SIZE           (5 * 1024 * 1024 / 2)
#define AGP_APERTURE_BYTES              (64*1024*1024)
#define INSTANCE_MEM_MAXSIZE            (20*1024)
#define NV_INSTANCE_SIZE                (INSTANCE_MEM_MAXSIZE)

//------------------------------------------------------------------------
// Starts the animation which will run on a background thread.  This API
// returns immediately.
//

BOOL g_bShortVersion;

void AniStartAnimation(BOOLEAN fShort)
{
    NTSTATUS Status;

    if (gBootAnimation_DoAnimation){

        g_bShortVersion = fShort;

        Status = PsCreateSystemThreadEx(&g_hThread,
                                        0,
                                        0x4000,  // Stack size, 16K
                                        0,
                                        NULL,
                                        NULL,
                                        NULL,
                                        FALSE,
                                        FALSE,
                                        AnipStartAnimationThread);

        if (!NT_SUCCESS(Status))
        {
            // RIP(("AniStartAnimation - Unable to create thread."));
            g_hThread = NULL;
        }
    }
}

//------------------------------------------------------------------------
// Shut down the animation.  This will block until the animation finishes.
//
void AniTerminateAnimation()
{
    if (g_hThread)
    {
        NTSTATUS Status;
#if DBG
        int start = NtGetTickCount();
#endif

        // Wait for it to go away.
        Status = NtWaitForSingleObjectEx(g_hThread, KernelMode, FALSE, NULL);

#if DBG
        DbgPrint("Boot animation wait %d\n", NtGetTickCount() - start);

        if (Status == STATUS_TIMEOUT)
        {
            //RIP(("AniTerminateAnimation - Animation is stuck!"));
        }
#endif

        NtClose(g_hThread);

        g_hThread = NULL;
    }
}

void AnipBreak()
{
#if DBG
   _asm int 3;
#endif
}

#if DBG
int gcMemAllocsContiguous = 0;
#endif

//------------------------------------------------------------------------
// Blocks until the animation has completed (until the animation is ready
// to display the Microsoft logo).
//
void AniBlockOnAnimation(void)
{
    extern KEVENT g_EventLogoWaiting;

    NTSTATUS status;
    PETHREAD ThreadObject;
    PVOID WaitObjects[2];
    KWAIT_BLOCK WaitBlocks[2];

    if (g_hThread)
    {
        status = ObReferenceObjectByHandle(g_hThread, &PsThreadObjectType,
            (PVOID*)&ThreadObject);

        if (NT_SUCCESS(status))
        {
            WaitObjects[0] = ThreadObject;
            WaitObjects[1] = &g_EventLogoWaiting;

            KeWaitForMultipleObjects(2, WaitObjects, WaitAny, Executive,
                KernelMode, FALSE, NULL, WaitBlocks);

            ObDereferenceObject(ThreadObject);
        }
    }
}

//------------------------------------------------------------------------
// MemAllocContiguous
//
void *MemAllocContiguous(size_t Size, DWORD Alignment)
{
#if DBG
    gcMemAllocsContiguous++;
#endif

    return MmAllocateContiguousMemoryEx(
            Size,
            0,
            AGP_APERTURE_BYTES - NV_INSTANCE_SIZE,
            Alignment,
            PAGE_READWRITE | PAGE_WRITECOMBINE);
}

//------------------------------------------------------------------------
// MemFreeContiguous
//
void MemFreeContiguous(void *pv)
{
#if DBG
    if (gcMemAllocsContiguous <= 0)
    {
        AnipBreak();
    }
    gcMemAllocsContiguous--;
#endif

    MmFreeContiguousMemory(pv);
}

//------------------------------------------------------------------------
// Main animation procedure.  Defers to the startup animation library.
//
VOID AnipStartAnimationThread(
    PKSTART_ROUTINE StartRoutine, 
    PVOID StartContext
    )
{
    AnipRunAnimation();

    // Make this thread go away.
    PsTerminateSystemThread(0);
}

///////////////////////////////////////////////////////////////////////////////
// Defined so we don't have to pull libc in
typedef void (__cdecl *_PVFV)(void);

int __cdecl atexit(_PVFV func)
{
    return 0;
}

///////////////////////////////////////////////////////////////////////////////
// Define a couple of debug-only methods used in XGRAPHICS that normally
// are implemented in XTL.

#ifdef STARTUPANIMATION

long __cdecl _ftol2(float x)
{
    DWORD result[2];
    unsigned short oldcw;
    unsigned short newcw;

    _asm
    {
        fstcw   [oldcw]         ; get control word
        fwait                   ; synchronize

        mov ax, [oldcw]         ; round mode saved
        or  ah, 0ch             ; set chop rounding mode
        mov [newcw], ax         ; back to memory

        fldcw   [newcw]         ; reset rounding
        fistp   qword ptr [result]  ; store chopped integer
        fldcw   [oldcw]         ; restore rounding

        mov eax, dword ptr [result]
        mov edx, dword ptr [result+4]
    }
}

#define D_EXP(x) ((unsigned short *)&(x)+3)
#define D_HI(x) ((unsigned long *)&(x)+1)
#define D_LO(x) ((unsigned long *)&(x))

#define IS_D_QNAN(x)    ((*D_EXP(x) & 0x7ff8) == 0x7ff8)
#define IS_D_SNAN(x)    ((*D_EXP(x) & 0x7ff8) == 0x7ff0 && \
                         (*D_HI(x) << 13 || *D_LO(x)))
                         
int __cdecl _isnan(double x)
{
    if (IS_D_SNAN(x) || IS_D_QNAN(x)) {
        return 1;
    }
    return 0;
}

VOID
XDebugError(PCHAR Module, PCHAR Format, ...)
{
    _asm int 3;
}

void Sleep(DWORD Milliseconds)
{
    _asm int 3;
}

VOID
OutputDebugStringA(
    IN LPCSTR lpOutputString
    )
{
    DbgPrint((PSTR)lpOutputString);
}

#endif

