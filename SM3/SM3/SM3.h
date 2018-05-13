#pragma once

#ifndef SM3_Hash_Algorithm_H
#define SM3_Hash_Algorithm_H

#include <iostream>
#include<stdint.h>
#include<string.h>
#include <vector>

using namespace std;

typedef uint32_t Word;
typedef uint8_t Byte;


class SM3
{
public:
	Word* SM3Hash(Byte *message, uint64_t length);

	//测试输出用的
	void PrintfByte(Byte *message, uint64_t length);
	void PrintfWord(Word *message, uint64_t length);

private:
	Word FF(Word X, Word Y, Word Z, int j);
	Word GG(Word X, Word Y, Word Z, int j);
	Word P0(Word X);
	Word P1(Word X);
	Word* CF(Word *V, Word *B);
	Word* CFF(vector<vector<Word>> message_grouped, uint64_t group_number);
	Byte* PadMessage(Byte *message, uint64_t length);
	Word* ExtendGroup(vector<Word> group);


	//功能函数
	int PaddingLength(uint64_t length);
	uint64_t SumLength(uint64_t length);
	Word ByteToWord(Byte *bytes);
	vector<vector<Word>> GroupingMessage(Byte *message, uint64_t length_sum);


	Word IV[8] = { 0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e };
	Word T_0to15 = 0x79cc4519;
	Word T_16to63 = 0x7a879d8a;
};


#endif SM3_Hash_Algorithm_H