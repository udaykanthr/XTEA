#include <stdint.h>
#include <stdio.h>
#include <string.h>


/* take 64 bits of data in v[0] and v[1] and 128 bits of key[0] - key[3] */
void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
  unsigned int i;
  uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
  for (i=0; i < num_rounds; i++) {
    v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    sum += delta;
    v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
  }
  v[0]=v0; v[1]=v1;
}


void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
  unsigned int i;
  uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*num_rounds;
  while(sum) {
    v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    sum -= delta;
    v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
  }
  v[0]=v0; v[1]=v1;
}


/*intializing Buffering stack*/
volatile int p =0;
volatile uint8_t buffer[100];
void push(const uint32_t b) {
  buffer[p] = (uint8_t)b;
  p++;
  buffer[p] = '\0';
}
/*Ending buffering stack*/


void writeBuffer(uint32_t v[2]) {  
  push(v[0] & 0x000000ff);
  push((v[0] & 0x0000ff00) >> 8);
  push((v[0] & 0x00ff0000) >> 16);
  push((v[0] & 0xff000000) >> 24);

  push(v[1] & 0x000000ff);
  push((v[1] & 0x0000ff00) >> 8);
  push((v[1] & 0x00ff0000) >> 16);
  push((v[1] & 0xff000000) >> 24);
}

void doBlock(uint8_t *d, uint8_t *key, int isEncrypt) {
  uint32_t k[4];
  k[0] = key[3]<<24 | key[2]<<16 | key[1]<<8 | key[0];
  k[1] = key[7]<<24 | key[6]<<16 | key[5]<<8 | key[4];
  k[2] = key[11]<<24 | key[10]<<16 | key[9]<<8 | key[8];
  k[3] = key[15]<<24 | key[14]<<16 | key[13]<<8 | key[12];
  int i=0;
  int n=0;
  uint32_t v[2];
  /* printf("\n encripting: %*s\n", 57, d); */
  int len = strlen(d);
  for (i=0; i < len; i = i+4) {
    if ((i+3) < len) {
      if (n == 0) {
        v[0] = d[i+3]<<24 | d[i+2]<<16 | d[i+1]<<8 | d[i];
        n = 1;
      } else if (n == 1) {
        v[1] = d[i+3]<<24 | d[i+2]<<16 | d[i+1]<<8 | d[i];
        n = 0;
        if(isEncrypt) {
          encipher(32, v, k);
        } else {
          decipher(32, v, k);
        }
        writeBuffer(v);
      }
    } else {
      int empty = (i + 3) - len;
      switch (empty) {
      case 1: {
        if (n==0) {
          v[0] = 0<<24 | d[i+2]<<16 | d[i+1]<<8 | d[i];
          v[1] = 0;
        } else {
          v[0] = 0;
          v[1] = 0<<24 | d[i+2]<<16 | d[i+1]<<8 | d[i];
        }
        break;
      }
      case 2: {
        if (n==0) {
          v[0] = 0<<24 | 0<<16 | d[i+1]<<8 | d[i];
          v[1] = 0;
        } else {
          v[0] = 0;
          v[1] = 0<<24 | 0<<16 | d[i+1]<<8 | d[i];
        }
        break;
      }
      case 3: {
        if (n==0) {
          v[0] = 0<<24 | 0<<16 | 0<<8 | d[i];
          v[1] = 0;
        } else {
          v[0] = 0;
          v[1] = 0<<24 | 0<<16 | 0<<8 | d[i];
        }
        break;
      }          
      default:
        v[0] = 0;
        v[1] = 0;
        break;
      }
      if(isEncrypt) {
        encipher(32, v, k);
      } else {
        decipher(32, v, k);
      }
      writeBuffer(v);
    }

  }

  printf("encrypted/decrepted string is:\n");
  printf("HEX:\n");
  for(i=0;i<32;i++) {
    printf("%0x ", buffer[i]);
  }
  printf("\n");
  printf("Chars:\n");
  for(i=0;i<32;i++) {
    printf("%c", buffer[i]);
  }
  printf("\n");
}


void encrypt(uint8_t *d, uint8_t *key) {
  doBlock(d, key, 1);
}

void decrypt(uint8_t *d, uint8_t *key) {
  doBlock(d, key, 0);
}
int main() {

  uint8_t *d = "This is a sample encryption TEXT";
  //  
  /* uint8_t d[] = {af1b916ca51b3c46b7bc5d397c71d7317656933577a222e49e5e4f28637a67239252df062b4a43a7}; */
  /* uint8_t d[] = {0xaf, 0x1b, 0x91, 0x6c, 0xa5, 0x1b, 0x3c, 0x46, 0xb7, 0xbc, 0x5d, 0x39, 0x7c, 0x71, 0xd7, 0x31, 0x76, 0x56, 0x93, 0x35, 0x77, 0xa2, 0x22, 0xe4, 0x9e, 0x5e, 0x4f, 0x28, 0x63, 0x7a, 0x67, 0x23, 0x92, 0x52, 0xdf, 0x06, 0x2b, 0x4a, 0x43, 0xa7,}; */
  
  /* uint8_t *key = "mmmmmmmmmmmmmmmm"; */
  // ed 10 b7 40 1c d3 4f c1 b2 26 97 d7 f6 16 47 a2
  // 54 49 31 38 32 34 33 35 36 37 33 34 39 31 53 5f
  uint8_t key[] = {0x54, 0x49, 0x31, 0x38, 0x32, 0x34, 0x33, 0x35, 0x36, 0x37, 0x33, 0x34, 0x39, 0x31, 0x53, 0x5f,};
  p=0;
  encrypt(d, key);
  uint8_t e_data[100];
  int i=0;
  /* int len = strlen(d); */
  for (i=0;i<32;i++) {
    e_data[i] = buffer[i];
  }
  p=0;
  decrypt(e_data, key);

  printf("ThankYou!");
  return 0;
}
