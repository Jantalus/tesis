#include <stdio.h>
#include <vector>

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
void myFunction(int a, int b, int c) {
  int myTenPositionVector[10];

  for (int primerIndice = 0; primerIndice < 10; primerIndice++)
  {
    myTenPositionVector[primerIndice] = a;
  }

  for (int segundoIndice = 0; segundoIndice < 10; segundoIndice++)
  {
    myTenPositionVector[segundoIndice] = b;
  }


  int miSumaTotal = 0;

  for (int cuartoIndice = 0; cuartoIndice < 10; cuartoIndice++)
  {
    miSumaTotal = miSumaTotal + myTenPositionVector[cuartoIndice];
  }
  for (int quintoIndice = 0; quintoIndice < 10; quintoIndice = quintoIndice + 2)
  {
    miSumaTotal = miSumaTotal + 2 * myTenPositionVector[quintoIndice] + c;
  }

  FILE *fid = fopen("caca.txt", "w");
  if (fid == nullptr)
  {
    perror("Error opening file");
    return;
  }
  fprintf(fid, "Mi suma total = %d\n", miSumaTotal);
  fclose(fid);

  /*
  auto a = asd->bla;
  printf("Auto variable del struct a=%d\n", a);
   */
}

int main()
{
  double myOtherVectorOfUnrelevantSize[20];

  for (int tercerIndice = 0; tercerIndice < 20; tercerIndice++)
  {
    myOtherVectorOfUnrelevantSize[tercerIndice] = (double) tercerIndice;
  }

  int miSegundaSumaTotal = 0;

  for (int tercerIndice = 0; tercerIndice < 20; tercerIndice++)
  {
    miSegundaSumaTotal = miSegundaSumaTotal + myOtherVectorOfUnrelevantSize[tercerIndice];
  }

  FILE *fid = fopen("caca2.txt", "w");
  if (fid == nullptr)
  {
    perror("Error opening file");
    return 1;
  }
  fprintf(fid, "Mi suma total = %d\n", miSegundaSumaTotal);
  fclose(fid);

  myFunction(1, 2, 3);

  return 0;
}

