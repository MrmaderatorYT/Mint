typedef enum MintColor { MintRed=-1, MintGreen=2 } MintColor;
typedef struct MintNode { int value; struct MintNode* next; } MintNode;
MintNode mint_debug_global={7,0};
int mint_debug_array[3]={1,2,3};
MintColor mint_debug_color=MintRed;
__attribute__((noinline)) int mint_debug_entry(int value,MintNode* node) {
    int local=value+mint_debug_array[1];
    node->value=local;
    return node->value+(int)mint_debug_color;
}
