#include <stdlib.h>
#include <stdio.h>

#include "linked_list.h"

Cell *create_cell(unsigned short val, Cell *cp);
int delete_cell(Cell *cp);
Cell *select_cell(Cell *cp, int n);

Cell *create_cell(unsigned short val, Cell *cp) {
    Cell *newcp;
    
    newcp = (Cell *)malloc(sizeof(Cell));
    if (newcp != NULL) {
        newcp->item = val;
        newcp->next = cp;
    }
    return newcp;
}

List *create_list(void) {
    List *ls;
    
    ls = (List *)malloc(sizeof(List));
    if (ls != NULL) {
        ls->top = create_cell(0, NULL);
        if (ls->top == NULL) {
            free(ls);
            return NULL;
        }
        ls->len = 0;
    }
    return ls;
}

int delete_cell(Cell *cp) {
    Cell *temp;
    int count = 0;

    while (cp != NULL) {
        temp = cp->next;
        free(cp);
        cp = temp;
        count++;
    }
    return count;
}

void delete_list(List *ls) {
    delete_cell(ls->top);
    free(ls);
}

Cell *select_cell(Cell *cp, int n) {
    int i;

    for (i = -1; cp != NULL; i++) {
        if (i == n) {
            break;
        }
        cp = cp->next;
    }
    return cp;
}

List_Get_Result get_value(List *ls, int n) {
    Cell *cp;
    List_Get_Result res;
    
    cp = select_cell(ls->top, n);
    if (cp == NULL) {
        res.err = false;
        res.value = 0;
        return res;
    }
    res.err = true;
    res.value = cp->item;
    return res;
}

bool insert_value(List *ls, int n, unsigned short x) {
    Cell *cp;
    
    cp = select_cell(ls->top, n - 1);
    if (cp == NULL) {
        return false;
    }
    cp->next = create_cell(x, cp->next);
    ls->len++;
    return true;
}

bool push(List *ls, unsigned short x) {
    return insert_value(ls, 0, x);
}

bool delete_value(List *ls, int n) {
    Cell *temp;
    Cell *cp;
    
    cp = select_cell(ls->top, n - 1);
    if (cp == NULL || cp->next == NULL) {
        return false;
    }
    temp = cp->next;
    cp->next = cp->next->next;
    free(temp);
    ls->len--;
    return true;
}

List_Get_Result pop(List *ls) {
    List_Get_Result res;
    
    res = get_value(ls, 0);
    if (res.err) {
        delete_value(ls, 0);
    }
    return res;
}

bool enqueue(List *ls, unsigned short x) {
    return push(ls, x);
}

List_Get_Result dequeue(List *ls) {
    List_Get_Result res;
    
    res = get_value(ls, list_length(ls) - 1);
    if (res.err) {
        delete_value(ls, list_length(ls) - 1);
    }
    return res;
}

bool is_empty_list(List *ls) {
  return (ls->top->next == NULL);
}

unsigned int list_length(List *ls) {
  return ls->len;
}

void print_list(List *ls) {
    printf("( ");
    for (Cell *cp = ls->top->next; cp != NULL; cp = cp->next) {
        printf("%d ", cp->item);
    }
    printf(")\n");
}
