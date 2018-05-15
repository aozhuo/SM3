// SM3_C.cpp : �������̨Ӧ�ó������ڵ㡣
//����д���ˣ���û���Դ��ļ����������

#include "stdafx.h"
#include "SM3.h"

#define RringShiftLeft(X, n) (((X << n))|(X >> (32 - n)))

Word SM3::FF(Word X, Word Y, Word Z, int j)
{
	if (j >= 0 && j <= 15)
	{
		return X^Y^Z;
	}
	else
	{
		return (X & Y) | (X & Z) | (Y & Z);
	}
}

Word SM3::GG(Word X, Word Y, Word Z, int j)
{
	if (j >= 0 && j <= 15)
	{
		return X^Y^Z;
	}
	else
	{
		return (X & Y) | (~X & Z);
	}
}

Word SM3::P0(Word X)
{
	return X ^ (RringShiftLeft(X, 9)) ^ (RringShiftLeft(X, 17));
}

Word SM3::P1(Word X)
{
	return X ^ (RringShiftLeft(X, 15)) ^ (RringShiftLeft(X, 23));
}

//����padding�ĳ���
int SM3::PaddingLength(uint64_t length)
{
	//ӦΪҪ�����һbit��1����������length��Ҫ+1
	return ((length + 1) % 64 > 56) ? (64 + 56 - (length + 1) % 64) : (56 - (length + 1) % 64);
}

//���ĸ�Byte�ϳ�һ��Word
Word SM3::ByteToWord(Byte *bytes)
{
	Word compound = 0x00000000;
	for (int i = 0;i < 4;i++)
	{
		compound = compound | (((Word)bytes[i]) << (24 - i * 8));
	}
	return compound;
}

//����������Ϣ���ܳ���
uint64_t SM3::SumLength(uint64_t length)
{
	return length + 1 + PaddingLength(length) + 8;
}

Byte* SM3::PadMessage(Byte *message, uint64_t length)
{
	int length_padding = PaddingLength(length);
	uint64_t length_sum = SumLength(length);
	Byte *message_padded = new Byte[length_sum]();
	memcpy(message_padded, message, length);
	message_padded[length] = 0x80;
	for (int i = 1;i <= length_padding;i++)
	{
		message_padded[length + i] = 0x00;
	}
	for (int i = 0;i < 8;i++)
	{
		Byte temp = (length * 8) >> (8 * i);
		message_padded[length_sum - 1 - i] = temp;
	}
	return message_padded;
}

//����Ϣ���з��飬64��Byte��16��Word��һ��
vector<vector<Word>> SM3::GroupingMessage(Byte *message, uint64_t length_sum)
{
	uint64_t group_number = length_sum / 64;
	vector<vector<Word>> message_grouped(group_number);
	for (int i = 0;i < group_number;i++)
	{
		vector<Word> group_temp(16);
		for (int j = 0;j < 16;j++)
		{
			group_temp[j] = ByteToWord(message + (i * 64 + j * 4));
		}
		message_grouped[i] = group_temp;
	}
	return message_grouped;
}

Word* SM3::ExtendGroup(vector<Word> group)
{
	Word *group_extended = new Word[132]();
	for (int i = 0;i < 16;i++)
	{
		group_extended[i] = group[i];
	}
	for (int i = 16;i < 68;i++)
	{
		group_extended[i] = P1(group_extended[i - 16] ^ group_extended[i - 9] ^ RringShiftLeft(group_extended[i - 3], 15)) ^ RringShiftLeft(group_extended[i - 13], 7) ^ group_extended[i - 6];
	}
	for (int i = 68;i < 132;i++)
	{
		group_extended[i] = group_extended[i - 68] ^ group_extended[i - 64];
	}
	return group_extended;
}

//һ���ѹ������
Word* SM3::CF(Word *V, Word *B)
{
	Word *message_hash = new Word[8]();
	Word SS1, SS2, TT1, TT2, T;
	memcpy(message_hash, V, 32);
	for (int i = 0;i < 64;i++)
	{
		T = (i < 16) ? T_0to15 : T_16to63;
		SS1 = RringShiftLeft(RringShiftLeft(message_hash[0], 12) + message_hash[4] + RringShiftLeft(T, i), 7);
		SS2 = SS1^RringShiftLeft(message_hash[0], 12);
		TT1 = FF(message_hash[0], message_hash[1], message_hash[2], i) + message_hash[3] + SS2 + B[i + 68];
		TT2 = GG(message_hash[4], message_hash[5], message_hash[6], i) + message_hash[7] + SS1 + B[i];
		message_hash[3] = message_hash[2];
		message_hash[2] = RringShiftLeft(message_hash[1], 9);
		message_hash[1] = message_hash[0];
		message_hash[0] = TT1;
		message_hash[7] = message_hash[6];
		message_hash[6] = RringShiftLeft(message_hash[5], 19);
		message_hash[5] = message_hash[4];
		message_hash[4] = P0(TT2);
	}
	for (int i = 0;i < 8;i++)
	{
		message_hash[i] = message_hash[i] ^ V[i];
	}
	return message_hash;
}


//���壨���飩��ѹ������
Word* SM3::CFF(vector<vector<Word>> message_grouped, uint64_t group_number)
{
	Word* V = new Word[8]();
	memcpy(V, IV, 32);
	for (int i = 0;i < group_number;i++)
	{
		//���������132��Word
		Word* group_extended = ExtendGroup(message_grouped[i]);
		//ѭ��ѹ��
		Word* last_V = CF(V, group_extended);
		memcpy(V, last_V, 32);
		//�ͷſռ�
		delete[] group_extended;
		delete[] last_V;
	}
	return V;
}

//�ܵ��Ӵ��㷨
Word* SM3::SM3Hash(Byte *message, uint64_t length)
{
	//�����ܳ��Ⱥͷ�����
	uint64_t length_sum = SumLength(length);
	uint64_t group_number = length_sum / 64;
	//����Ϣ�������
	Byte* message_padded = PadMessage(message, length);
	//����Ϣ���з���
	vector<vector<Word>> message_grouped = GroupingMessage(message_padded, length_sum);
	delete[] message_padded;
	return CFF(message_grouped, group_number);
}


//���ڵ������Byte�������ݣ���ʮ��������ʽ
void SM3::PrintfByte(Byte *message, uint64_t length)
{
	for (int i = 0;i < length;i++)
	{
		cout << hex << int(message[i]) << ' ';
	}
	cout << endl;
}

//���ڵ������Word�������ݣ���ʮ��������ʽ
void SM3::PrintfWord(Word *message, uint64_t length)
{
	for (int i = 0;i < length;i++)
	{
		cout << hex << message[i] << ' ';
	}
	cout << endl;
}