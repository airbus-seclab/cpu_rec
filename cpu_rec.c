/* Four times faster than the python version, but not intended for
 * normal use: no sliding window, displays the KL distance from the
 * whole file to every known architecture. */
/* Eats a lot of memory, because the statistics are computed in non-parse
 * structures; makes the assumption that the uncompressed corpus is in BASEDIR
 * aka. "/tmp/cpu_rec_corpus". */
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <math.h>

int verbose = 0;

#define BUFSIZE 80
#define M2C (256*256)
#define M3C (256*256*256)
#define fp_t double
struct stats {
  fp_t *m2, *m3;
  char *arch;
};

void increment(struct stats r, unsigned char *buffer, size_t c)
{
  size_t i;
  for (i=2; i<c; i++) {
    r.m2[ buffer[i] + 256*buffer[i-1] ] += 1;
    r.m3[ buffer[i] + 256*buffer[i-1] + 256*256*buffer[i-2] ] += 1;
  }
}

struct stats count_ngrams(char *filename)
{
  /* Allocate 128 Mbytes */
  FILE *f;
  struct stats r;
  unsigned char buffer[BUFSIZE];
  unsigned char prv, prv2;
  size_t c;
  f = fopen(filename, "rb");
  if (f==NULL) { perror(filename); exit(EXIT_FAILURE); }
  r.m2 = malloc(M2C*sizeof(fp_t));
  if (r.m2 == NULL) { perror("malloc failed"); exit(EXIT_FAILURE); }
  r.m3 = malloc(M3C*sizeof(fp_t));
  if (r.m3 == NULL) { perror("malloc failed"); exit(EXIT_FAILURE); }
  c = fread(buffer, 1, BUFSIZE, f);
  if (c>1)
    r.m2[ buffer[1] + 256*buffer[0] ] += 1;
  increment(r, buffer, c);
  while (c) {
    buffer[0] = buffer[BUFSIZE-2];
    buffer[1] = buffer[BUFSIZE-1];
    c = fread(buffer+2, 1, BUFSIZE-2, f);
    increment(r, buffer, c+2);
  }
  fclose(f);
  return r;
}

void make_frequencies(struct stats s, fp_t base)
{
  size_t i;
  fp_t somme;
  somme = 0;
  for (i=0; i<M2C; i++) {
    s.m2[i] += base;
    somme += s.m2[i];
  }
  for (i=0; i<M2C; i++)
    s.m2[i] /= somme;
  somme = 0;
  for (i=0; i<M3C; i++) {
    s.m3[i] += base;
    somme += s.m3[i];
  }
  for (i=0; i<M3C; i++)
    s.m3[i] /= somme;
}

#define BASEDIR "/tmp/cpu_rec_corpus"
#define MAX_ARCH 1000
struct stats *read_corpus()
{
  size_t h, i;
  struct stats *s;
  DIR *d;
  d = opendir(BASEDIR);
  if (d==NULL) { perror(BASEDIR); exit(EXIT_FAILURE); }
  s = malloc(MAX_ARCH*sizeof(struct stats));
  h = 0;
  while (1) {
    char filename[100];
    struct dirent *f = readdir(d);
    if (f==NULL) break;
    uint8_t d_namlen = strlen(f->d_name);
    if ((d_namlen<7) || strcmp(f->d_name+d_namlen-7,".corpus")) continue;
    snprintf(filename, 100, BASEDIR "/%s", f->d_name);
    if (verbose) printf("* %s\n", filename);
    s[h] = count_ngrams(filename);
    s[h].arch = strndup(f->d_name,d_namlen-7);
    /*
    for (i=0; i<M2C; i++)
      if (s[h].m2[i])
        if (verbose) printf("0x%04zx %f\n", i, s[h].m2[i]);
    for (i=0; i<M3C; i++)
      if (s[h].m3[i])
        if (verbose) printf("0x%06zx %f\n", i, s[h].m3[i]);
    */
    make_frequencies(s[h], 0.01);
    h++;
    if (h>=MAX_ARCH) break;
  }
  return s;
}

fp_t KLdivergence(fp_t *P, fp_t *Q, size_t sz)
{
  size_t i;
  fp_t k = 0;
  for (i=0; i<sz; i++)
    if (P[i])
      k += P[i] * log(P[i]/Q[i]);
  return k;
}

int main(int argc, char **argv)
{
  size_t h, i;
  struct stats *corpus = read_corpus();
  verbose = 1;
  for (i=1; i<argc; i++) {
    struct stats c = count_ngrams(argv[i]);
    make_frequencies(c, 0);
    for (h=0; h<MAX_ARCH; h++) {
      if (!corpus[h].arch) break;
      fp_t k2 = KLdivergence(c.m2, corpus[h].m2, M2C);
      fp_t k3 = KLdivergence(c.m3, corpus[h].m3, M3C);
      if (verbose) printf("%10s %f %f\n", corpus[h].arch, k2, k3);
    }
  }
}
