/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2015 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
//
// This tool counts the number of times a routine is executed and 
// the number of instructions executed in a routine
//

#include <fstream>
#include <iomanip>
#include <iostream>
#include <string.h>
#include "pin.H"
#include <map>

ofstream outFile;

map<string, vector<pair<UINT64, UINT64> > > RtnToRead;
static UINT64 icount_begin = 0;
static UINT64 icount_func = 0;

VOID RecordMemRead(ADDRINT address, UINT64 memOp, string rname) {
    if (rname != "_gcry_mpi_powm") {
	icount_begin ++;
    }
    if (rname == "_gcry_mpi_powm") {
	icount_func ++;
    }
    RtnToRead[rname].push_back(make_pair(address, memOp));
}

// Holds instruction count for a single procedure
typedef struct RtnCount
{
    string _name;
    string _image;
    ADDRINT _address;
    RTN _rtn;
    UINT64 _rtnCount;
    UINT64 _icount;
    struct RtnCount * _next;
} RTN_COUNT;

// Linked list of instruction counts for each routine
RTN_COUNT * RtnList = 0;

// This function is called before every instruction is executed
VOID docount(UINT64 * counter)
{
    (*counter)++;
}
    
const char * StripPath(const char * path)
{
    const char * file = strrchr(path,'/');
    if (file)
        return file+1;
    else
        return path;
}



// This function is called when the application exitsOutFile
// It prints the name and count for each procedure
VOID Fini(INT32 code, VOID *v)
{
    cout << "_gcry_mpi_powm begins at ins count: " << icount_begin << endl;
    cout << "_gcry_mpi_powm ins count: " << icount_func << endl;
    map<string, vector<pair<UINT64, UINT64> > > :: iterator it = RtnToRead.begin();
    while(it != RtnToRead.end())
    {
	cout << it->first << " :" << endl;
	vector<pair<UINT64, UINT64> > :: iterator ip = it->second.begin();
 	while(ip != it->second.end())
	{
		// cout << "\t" << hex << ip->first << " : " << ip->second << endl;
		++ip;
	}
	++it;
	}

}



VOID Routine(RTN rtn, VOID *v) {

    RTN_Open(rtn);

    string name = RTN_Name(rtn);

    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {

        UINT32 memOperands = INS_MemoryOperandCount(ins);
        for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
            if (INS_MemoryOperandIsRead(ins, memOp)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                         (AFUNPTR)RecordMemRead, IARG_INST_PTR,
                                         IARG_MEMORYOP_EA, memOp, IARG_PTR,
                                         new string(name), IARG_END);
            }
        }
    }

    RTN_Close(rtn);
}
/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This Pintool counts the number of times a routine is executed" << endl;
    cerr << "and the number of instructions executed in a routine" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    // Initialize symbol table code, needed for rtn instrumentation
    PIN_InitSymbols();

    outFile.open("proccount.out");

    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    // Register Routine to be called to instrument rtn
    RTN_AddInstrumentFunction(Routine, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
