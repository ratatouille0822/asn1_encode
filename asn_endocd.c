#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "itcast_asn1_der.h"
#include "itcastderlog.h"

typedef struct teacher_t
{
	char name[32];
	int age;
	char* p;
	int len;
} teacher_t;

int write_file(char* buffer, int buffer_len)
{
	int ret = -1;
	FILE* fp = NULL;
	fp = fopen("D:\\teacher.ber", "w+");
	if (NULL == fp)
	{
		perror("fopen");
		return 1;
	}
	ret = fwrite(buffer, 1, buffer_len, fp);
	if (-1 == ret)
	{
		perror("fwrite");
		fclose(fp);
		return 1;
	}
	fclose(fp);

	return 0;
}

int encode_teacher(const struct teacher_t* t, unsigned char** out_stream, unsigned int* out_len)
{
	ITCAST_INT ret = -1;
	ITCAST_ANYBUF* node_name = NULL;
	ITCAST_ANYBUF* head_node = NULL;
	ITCAST_ANYBUF* temp = NULL;
	ITCAST_ANYBUF* out_data = NULL;

	char* data = NULL;
	
	ret = DER_ITCAST_String_To_AnyBuf(&node_name, t->name, strlen(t->name)); // free(node_name);
	if (-1 == ret)
	{
		printf("DER_ITCAST_String_To_AnyBuf failed...\n");
		goto err0;
	}

	//name -> anybuffer

	ret = DER_ItAsn1_WritePrintableString(node_name, &head_node);
	if (-1 == ret)
	{
		printf("DER_ItAsn1_WritePrintableString failed...\n");
		goto err0;
	}

	//int age -> anybuffer
	temp = head_node;

	ret = DER_ItAsn1_WriteInteger(t->age, &(temp->next));
	if (-1 == ret)
	{
		printf("DER_ItAsn1_WriteInteger failed...\n");
		goto err0;
	}

	//char* p -> anybuffer

	temp = temp->next;
	ret = EncodeChar(t->p, t->len, &(temp->next));
	if (-1 == ret)
	{
		printf("Encodechar failed...\n");
		goto err0;
	}

	//int len -> anybuffer
	temp = temp->next;
	ret = DER_ItAsn1_WriteInteger(t->len, &(temp->next)); // free(temp);
	if (-1 == ret)
	{
		printf("DER_ItAsn1_WriteInteger failed...\n");
		goto err0;
	}

	//write structure

	ret = DER_ItAsn1_WriteSequence(head_node, &out_data);//free(head_node);
	if (0 != ret)
	{
		printf("DER_ItAsn1_WriteSequence failed\n");
		goto err0;
	}

	data = malloc(out_data->dataLen + 1);
	if(NULL == data)
	{
		printf("malloc failed\n");
		goto err0;
	}
	memset(data, 0, out_data->dataLen + 1);
	memcpy(data, out_data->pData, out_data->dataLen);

	*out_stream = data;
	*out_len = out_data->dataLen;

	if (NULL != node_name)
	{
		DER_ITCAST_FreeQueue(node_name);
	}
	if (NULL != head_node)
	{
		DER_ITCAST_FreeQueue(head_node);
	}
	if (NULL != out_data)
	{
		DER_ITCAST_FreeQueue(out_data);
	}

	return 0;
err0:
	if (NULL != node_name)
	{
		DER_ITCAST_FreeQueue(node_name);
	}
	if (NULL != head_node)
	{
		DER_ITCAST_FreeQueue(head_node);
	}
	if (NULL != out_data)
	{
		DER_ITCAST_FreeQueue(out_data);
	}
	return 1;
}

int decode_teacher(const unsigned char* in_data, int len, struct teacher_t** p_teacher)
{
	ITCAST_INT ret = -1;
	ITCAST_ANYBUF* node_data = NULL;
	ITCAST_ANYBUF* head_node = NULL;
	ITCAST_ANYBUF* temp = NULL;
	ITCAST_ANYBUF* node_name = NULL;
	ITCAST_ANYBUF* node_p = NULL;

	struct teacher_t* p_t = NULL;

	
	ret = DER_ITCAST_String_To_AnyBuf(&node_data, in_data, len);
	if (0 != ret)
	{
		printf("DER_ITCAST_String_To_AnyBuf failed...\n");
		goto err0;
	}

	ret = DER_ItAsn1_ReadSequence(node_data, &head_node);
	if (0 != ret)
	{
		printf("DER_ItAsn1_ReadSequence failed...\n");
		goto err0;
	}

	p_t = malloc(sizeof(struct teacher_t));
	if (NULL == p_t)
	{
		perror("malloc");
		goto err0;
	}
	memset(p_t, 0, sizeof(struct teacher_t));

	ret = DER_ItAsn1_ReadPrintableString(head_node, &node_name);
	if (0 != ret)
	{
		printf("DER_ItAsn1_ReadPrintableString failed...\n");
		goto err0;
	}
	memcpy(p_t->name, node_name->pData, node_name->dataLen);

	temp = head_node->next;
	ret = DER_ItAsn1_ReadInteger(temp, &p_t->age);
	if (0 != ret)
	{
		printf("DER_ItAsn1_ReadInteger failed...\n");
		goto err0;
	}

	temp = temp->next;
	ret = DER_ItAsn1_ReadPrintableString(temp, &node_p);
	if (0 != ret)
	{
		printf("DER_ItAsn1_ReadPrintableString failed...\n");
		goto err0;
	}

	p_t->p = malloc(node_p->dataLen + 1);
	if (NULL == p_t->p)
	{
		perror("malloc");
		goto err0;
	}
	memset(p_t->p, 0, node_p->dataLen + 1);
	memcpy(p_t->p, node_p->pData, node_p->dataLen);

	temp = temp->next;

	ret = DER_ItAsn1_ReadInteger(temp, &p_t->len);
	if (0 != ret)
	{
		printf("DER_ItAsn1_ReadInteger failed...\n");
		goto err0;
	}
	
	*p_teacher = p_t;

	if (NULL != node_data)
	{
		DER_ITCAST_Free(node_data);
	}
	if (NULL != head_node)
	{
		DER_ITCAST_Free(head_node);
	}
	if (NULL != node_name)
	{
		DER_ITCAST_Free(node_name);
	}
	if (NULL != node_p)
	{
		DER_ITCAST_Free(node_p);
	}

	return 0;
err0:
	if (NULL != node_data)
	{
		DER_ITCAST_Free(node_data);
	}
	if (NULL != head_node)
	{
		DER_ITCAST_Free(head_node);
	}
	if (NULL != node_name)
	{
		DER_ITCAST_Free(node_name);
	}
	if (NULL != node_p)
	{
		DER_ITCAST_Free(node_p);
	}
	return 1;
}

int free_teacher(struct teacher_t** t)
{
	struct teacher_t* p_teacher = NULL;
	if (NULL == t || NULL == *t)
	{
		printf("NULL");
		return -1;
	}
	 
	p_teacher = *t;

	if (NULL != p_teacher)
	{
		free(p_teacher->p);
	}

	free(p_teacher);

	*t = NULL;

	return 0;

}


int main()
{
	struct teacher_t* p_teacher = NULL;
	struct teacher_t t = {
		.name = "Kitty",
		.age = 18,
		.p = "test encode",
		.len = strlen("test_encode")
	};

	char* buffer = NULL;
	int len = 0;

	encode_teacher(&t, &buffer, &len);
	write_file(buffer, len);

	decode_teacher(buffer, len, &p_teacher);

	if (p_teacher->age == t.age || strcmp(p_teacher->name, t.name) == 0)
	{
		printf("Correct decoding...\n");
	}
	else
	{
		printf("Something wrong...\n");
	}

	printf("name = %s, age = %d, p = %s, len = %d\n", p_teacher->name, p_teacher->age, p_teacher->p, p_teacher->len);

	free_teacher(&p_teacher);

	printf("\033[31mtest colour\033[0m\n");

	return 0;
}