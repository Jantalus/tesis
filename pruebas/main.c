#include <stdio.h>
#include <ittnotify.h>

void print2DArray(int arr[20][30], int rows, int cols) {
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            printf("%d ", arr[i][j]);
        }
        printf("\n");
    }
}

int main() {
  __itt_domain* domain = __itt_domain_create("Example.Domain.Global");
  // Create string handles which associates with the "main" task.
  __itt_string_handle* handle_main = __itt_string_handle_create("MATIHANDLER");
  int matrix[4][5] = {0};

  __itt_task_begin(domain, __itt_null, __itt_null, handle_main);
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 5; j++) {
      matrix[i][j] = i+j;
      //printf("i: %d j:%d \n", i, j);
    }
  }
  __itt_task_end(domain);

  print2DArray(matrix, 4, 5);

  return 0;
}
