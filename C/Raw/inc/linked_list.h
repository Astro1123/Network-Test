#ifndef __LINKED_LIST_H__
#define __LINKED_LIST_H__

#include <stdbool.h>

typedef struct cell {
    unsigned short item;
    struct cell *next;
} Cell;

typedef struct {
    Cell *top;
    unsigned int len;
} List;

typedef struct {
    unsigned short value;
    bool err;
} List_Get_Result;

List *create_list(void);
void delete_list(List *ls);

List_Get_Result get_value(List *ls, int n);
bool insert_value(List *ls, int n, unsigned short x);
bool delete_value(List *ls, int n);

bool push(List *ls, unsigned short x);
List_Get_Result pop(List *ls);
bool enqueue(List *ls, unsigned short x);
List_Get_Result dequeue(List *ls);

bool is_empty_list(List *ls);
unsigned int list_length(List *ls);
void print_list(List *ls);

#endif /* __LINKED_LIST_H__ */
