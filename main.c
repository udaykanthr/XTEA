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
    for (i=0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}

volatile int p =0;
volatile uint8_t buffer[100];
void push(const uint32_t b) {
  buffer[p] = (uint8_t)b;
  p++;
  buffer[p] = '\0';
}
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
int main() {

  uint8_t *d = "This is a sample encryption TEXT";
  uint8_t *key = "mmmmmmmmmmmmmmmm";

  uint32_t k[4];
  k[0] = key[3]<<24 | key[2]<<16 | key[1]<<8 | key[0];
  k[1] = key[7]<<24 | key[6]<<16 | key[5]<<8 | key[4];
  k[2] = key[11]<<24 | key[10]<<16 | key[9]<<8 | key[8];
  k[3] = key[15]<<24 | key[14]<<16 | key[13]<<8 | key[12];

  int i=0;
  int n=0;
  uint32_t v[2];
  printf("\n encripting: %*s\n", 57, d);
 int len = strlen(d);
  for (i=0; d[i] != '\0'; i = i+4) {
    if ((i+3) < len) {
      if (n == 0) {
        v[0] = d[i+3]<<24 | d[i+2]<<16 | d[i+1]<<8 | d[i];
        n = 1;
      } else if (n == 1) {
        v[1] = d[i+3]<<24 | d[i+2]<<16 | d[i+1]<<8 | d[i];
        n = 0;
        encipher(32, v, k);
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
        encipher(32, v, k);
        writeBuffer(v);
    }

  }

  printf("encrypted string is %*s\n", 50, buffer);
  
  v[0] = 0;
  v[1] = 0;
  n = 0;
  uint8_t e_data[100];
  for (i=0;i<len;i++) {
    e_data[i] = buffer[i];
  }
  i=0;
  p=0;
  printf("length of string is %*d\n", 20, len);
  for (i=0; e_data[i] != '\0'; i = i+4) {
    if ((i+3) < len) {
      if (n == 0) {
        v[0] = e_data[i+3]<<24 | e_data[i+2]<<16 | e_data[i+1]<<8 | e_data[i];
        n = 1;
      } else if (n == 1) {
        v[1] = e_data[i+3]<<24 | e_data[i+2]<<16 | e_data[i+1]<<8 | e_data[i];
        n = 0;
        decipher(32, v, k);
        writeBuffer(v);
      }
    } else {
        int empty = (i + 3) - len;
        switch (empty) {
        case 1: {
          if (n==0) {
            v[0] = 0<<24 | e_data[i+2]<<16 | e_data[i+1]<<8 | e_data[i];
            v[1] = 0;
          } else {
            v[0] = 0;
            v[1] = 0<<24 | e_data[i+2]<<16 | e_data[i+1]<<8 | e_data[i];
          }
          break;
        }
        case 2: {
          if (n==0) {
            v[0] = 0<<24 | 0<<16 | e_data[i+1]<<8 | e_data[i];
            v[1] = 0;
          } else {
            v[0] = 0;
            v[1] = 0<<24 | 0<<16 | e_data[i+1]<<8 | e_data[i];
          }
          break;
        }
        case 3: {
          if (n==0) {
            v[0] = 0<<24 | 0<<16 | 0<<8 | e_data[i];
            v[1] = 0;
          } else {
            v[0] = 0;
            v[1] = 0<<24 | 0<<16 | 0<<8 | e_data[i];
          }
          break;
        }          
        default:
          v[0] = 0;
          v[1] = 0;
          break;
        }
        decipher(32, v, k);
        writeBuffer(v);
    }

  }

  /* printf("Decrpted string is %*s\n", 30, buffer); */
  printf("decrypted string is %*s\n", 50, buffer);
  printf("ThankYou!");
  return 0;
}
