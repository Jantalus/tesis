#include <stdio.h>
#include <vector>
#include <stdlib.h>
#include <ctime>
#include <thread>
#include <string>
#include <cstring>

//int globalMatrix[2][2] = {0};

//struct MyStruct {
//  int caca;
//  bool bla;
//};

//
//
// Agregame parametros y fijate como son los DIEs
//
//
void myFunction() {
  int myTenPositionVector[10];

  for (int i = 0; i < 10; i++) {
    myTenPositionVector[i] = i;
  }
}

void indireccion(int* miArr, int size) {
  int* copy = miArr;
  for (int i = 0; i < size; i++) {
    copy[i] = i;
  }
}

void indireccion2(int* miArr, int size) {
  for (int i = 0; i < size; i++) {
    miArr[i] = i*2;
  }
}

void instantiateAndWriteSomeArr() {
  int totalSize = 5;
  int *otherArr = (int *)malloc(totalSize * sizeof(int));

  for (int i = 0; i < totalSize; i++) {
    otherArr[i] = i + 1;
  }

  free(otherArr);
}

void indireccionString(char* punteroString) {
  std::strcpy(punteroString, "BLA");
}

int myFunction2(int a) {
  int myVar = 10;
  myVar = a + 2;

  return myVar;
}

int main() {
  int totalSize = 5;
  int *arr = (int *)malloc(totalSize * sizeof(int));

  for (int i = 0; i < totalSize; i++) {
    arr[i] = i * 10;
  }

  indireccion(arr, totalSize);

  time_t currentTime = time(NULL);
  struct tm *localTime = localtime(&currentTime);
  char *timestamp = (char *)malloc(20 * sizeof(char));
  if (timestamp != NULL) {
    strftime(timestamp, 20, "%Y-%m-%d %H:%M:%S", localTime);
  }

  char* hello = (char *)malloc(20 * sizeof(char));
  std::strcpy(hello, "Hello");

  char a = hello[1];
  printf("caca: %c", a);

  std::thread ts(indireccionString, hello);
  ts.join();

  int d = myFunction2(2);
  printf("myVar with 2: %d a", a);

  //for (int tercerIndice = 0; tercerIndice < 20; tercerIndice++)
  //{
  //  miSegundaSumaTotal = miSegundaSumaTotal + myOtherVectorOfUnrelevantSize[tercerIndice];
  //}



  FILE *fid = fopen("caca2.txt", "w");
  if (fid == nullptr)
  {
    perror("Error opening file");
    return 1;
  }
  //fprintf(fid, "Mi suma total = %d\n", miSegundaSumaTotal);
  fprintf(fid, "Mi dame algo = %d\n", arr[2]);
  fprintf(fid, "Mi timestamp = %s\n", timestamp);

  std::thread t(indireccion2, arr, totalSize);

  t.join();

  free(arr);

  free(timestamp);

  instantiateAndWriteSomeArr();
  std::thread t2(instantiateAndWriteSomeArr);
  t2.join();

  fclose(fid);

  myFunction();
  int rows = 3, cols = 4;

  // Allocate array of row pointers
  int** pointer = (int **)malloc(rows * sizeof(int *));
  int **matrix = pointer;

  // Allocate each row
  for (int i = 0; i < rows; ++i){
    matrix[i] = (int *)malloc(cols * sizeof(int));
  }

  for (int i = 0; i < rows; ++i){
    matrix[i][0] = i;
  }

  for (int i = 0; i < rows; ++i){
    matrix[i][2] = i;
  }

  matrix[1][2] = matrix[0][2] + 1;
  // matrix[2][3] = 42;
  // matrix[0][3] = 42;

  // int b = matrix[0][0] + 1;

  // // Free memory
  // for (int i = 0; i < rows; ++i){
  //   free(matrix[i]);
  // }

  free(matrix);

  int rows2 = 1, cols2 = 2, depth = 5;

    // Allocate array of pointers to pointers (for rows)
    int ***asd = (int ***)malloc(rows2 * sizeof(int **));

    // Allocate each row
    for (int i = 0; i < rows2; ++i) {
        asd[i] = (int **)malloc(cols2 * sizeof(int *));
        
        // Allocate each column for the current row
        for (int j = 0; j < cols2; ++j) {
            asd[i][j] = (int *)malloc(depth * sizeof(int));
        }
    }

    asd[0][1][3] = 42;

    // Free allocated memory
    for (int i = 0; i < rows2; ++i) {
        for (int j = 0; j < cols2; ++j) {
            free(asd[i][j]);
        }
        free(asd[i]);
    }
    free(asd);

   int* array = (int*) malloc(10 * sizeof(int));
  
   for (int i = 0; i < 10; i++){
    array[i] = i+1;
   }

   int myVar = 0;
   for (int i = 0; i < 10; i++){
    myVar += array[i] + 2*i;
   }

  

  return 0;
}



