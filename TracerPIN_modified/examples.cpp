#include <stdio.h>
#include <stdlib.h>
#include <ctime>
#include <thread>
#include <string>
#include <cstring>

int globalMatrix[4] = {0};

int primitiveType(int a) {
  int myVar = 10;
  myVar = a + 2;

  return myVar;
}

void fixedArray() {
  int myTenPositionVector[10];

  for (int i = 0; i < 10; i++) {
    myTenPositionVector[i] = i;
  }

  int a = myTenPositionVector[3];
}

void indirection(int* myArr, int size) {
  for (int i = 0; i < size; i++) {
    myArr[i] = i;
  }
}

void mallocAndWriteArray() {
  int totalSize = 5;
  int *otherArr = (int *)malloc(totalSize * sizeof(int));

  for (int i = 0; i < totalSize; i++) {
    otherArr[i] = i + 1;
  }

  int a = otherArr[3];

  free(otherArr);
}

void indirectionString(char* punteroString) {
  std::strcpy(punteroString, "BLA");
}


int main() {
  for(int i = 0; i < 4; i++)
    globalMatrix[i] = 15;

  // Ex 1
  int d = primitiveType(2);

  // Ex 2
  fixedArray();

  // Ex 3
  mallocAndWriteArray();

  // Ex 4
  int totalSize = 5;
  int *arr = (int *)malloc(totalSize * sizeof(int));

  for (int i = 0; i < totalSize; i++) {
    arr[i] = i * 10;
  }

  totalSize = arr[2];

  free(arr);

  // Ex 5
  int otherTotalSize = 3;
  int *otherArr = (int *)malloc(otherTotalSize * sizeof(int));
  for (int i = 0; i < otherTotalSize; i++) {
    otherArr[i] = i;
  }
  indirection(otherArr, otherTotalSize);
  free(otherArr);

  // Ex 6
  int anotherSize = 3;
  int *anotherArray = (int *)malloc(anotherSize * sizeof(int));
  indirection(otherArr, otherTotalSize);
  std::thread t(indirection, anotherArray, anotherSize);

  t.join();

  free(anotherArray);

  // Ex 7
  char* hello = (char *)malloc(20 * sizeof(char));
  std::strcpy(hello, "Hello");

  char a = hello[1]; // [R]

  free(hello);


  // Ex 8
  int rows = 3, cols = 4;

  // Allocate array of row pointers
  int** matrix = (int **)malloc(rows * sizeof(int *));

  // Allocate each row
  for (int i = 0; i < rows; ++i){
    matrix[i] = (int *)malloc(cols * sizeof(int));
    // each write in matrix[i] will add the 
    // region of memory to the list of "regions of interest"
  }

  for (int i = 0; i < rows; ++i){
    matrix[i][0] = i; // Reads m[i] for each write
  }

  for (int i = 0; i < rows; ++i){
    matrix[i][2] = i;
  }

  free(matrix);

  return 0;
}