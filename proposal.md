# GEARSHIFT IRAD proposal
## Name
GEARSHIFT (because we’re shifting between forward and reverse engineering)
## Summary
Creating fuzz harnesses is an important part of directing a fuzzer to particular code of interest while performing vulnerability research on a piece of software. Existing techniques exist to do this for source-assisted fuzzing, but the support for binary-only targets is limited or non-existent. This provides a particular issue when performing VR on Windows (or on closed-source software on other operating systems). We propose a research project that performs a mix of static and instrumented dynamic analysis of a binary to determine the function prototype at a specified address, to allow for semi-automated fuzz harness creation of a target function of interest within a binary-only target.
## State of the art
The state of the art in this space is primarily focused on source-assisted harnessing. I’ve been unable to find any projects that attempt to perform this sort of analysis on binary targets. The closest state of the art would be symbolic execution engines, which would be leveraged as a part of this project’s tooling to allow for rapid introspection of the code at the target address.
## Business Case
The advancement of the state of the art would allow us better targeted fuzzing of Windows targets when performing VR. The initial gain from this is obvious - we’re more likely to find bugs if we can target specific code.

The resulting capability would be leveraged within GRIMM to allow for better fuzzing, incorporated into the KILLERBEEZ (and other) fuzzing framework(s), and could (and probably should) also be released to the community to demonstrate GRIMM’s capabilities and dedication to community research.

## Expected LOE
As with most research tasks, an exact LOE is difficult to calculate. This proposal encompasses initial exploration into the concepts and an MVP that will demonstrate the ability to obtain some relevant symbolic information. A decision can then be made to continue to develop the capability or terminate the project.

A junior researcher will be expected to spend 400-440 hours on the initial research project. Senior/Director oversight and support will represent an addition of between 1/8th and 1/4 of that time (55-110 hours amortized as 1-2 hours per day).

## Equipment/Resources
Ideally, a Windows license would be used to allow for the continual use of a single registered VM. An IDA Pro and/or Binary Ninja license would also be of use (though existing licenses within the AppSec team may possibly be reused, these are named licenses that can’t normally be transferred to an intern). Ghidra may also be leveraged in place of these disassemblers, though my familiarity with its scripting and automation is considerably lower. A disassembler license is not required if the first phase of the project doesn’t attempt to leverage the disassembler’s scripting engine and instead leverages capstone and other open source engines.

