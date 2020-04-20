/* ctest.h
 * Author: Chuck Allison
 * Link: 
 *       The Simplest Automated Unit Test Framework That Could Possibly Work:
 *       http://www.ddj.com/184401279?pgno=1
 *
 * Source:
 *       ftp://66.77.27.238/sourcecode/cuj/2000/cujsep2000.zip
 *
 * Modified: 
 *       By Seth Ellsworth @ Quest.
 *
 * 
 *              Defines a test framework for C projects.
 * (c) 2007 Quest Software, Inc. All rights reserved.
 */
#ifndef CTEST_H
#define CTEST_H

#include <stdio.h>
#include "bool.h"

#define ct_test(test, cond) \
        ct_do_test(test, #cond, cond, __FILE__, __LINE__, __FUNCTION__)
#define ct_fail(test, str)  \
        ct_do_fail(test, str, __FILE__, __LINE__, __FUNCTION__)

typedef struct Test Test;
typedef void (*TestFunc)(Test*);

Test* ct_create(const char* name, void (*init)(Test*));
void ct_destroy(Test* pTest);

const char* ct_getName(Test* pTest);
long ct_getNumPassed(Test* pTest);
long ct_getNumFailed(Test* pTest);
long ct_getNumTests(Test* pTest);
FILE* ct_getStream(Test* pTest);
void ct_setStream(Test* pTest, FILE* stream);

bool ct_addTestFun(Test* pTest, TestFunc tfun);
void ct_succeed(Test* pTest);
long ct_run(Test* pTest);
long ct_report(Test* pTest);
void ct_reset(Test* pTest);

/* Not intended for end-users: */
void ct_do_test(Test* pTest, const char* str,
                                bool cond, const char* file, long line,const char*func);
void ct_do_fail(Test* pTest, const char* str,
                                const char* file, long line,const char*func);

#endif
