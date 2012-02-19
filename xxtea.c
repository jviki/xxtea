/*
 * xxtea.c - Source file
 * Crypt or decrypt given file. Blocks of 512B are ciphered, file is padded to the 512B 
 * boundary. XXTEA cipher is used.
 * Based on: 
 * David J. Wheeler and Roger M. Needham (October 1998). "Correction to XTEA".
 * Computer Laboratory, Cambridge University, England.
 * Author: Vlastimil Kosar <ikosar@fit.vutbr.cz> 
 */

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "crypto.h"

int print_help(const char *prog)
{
    fprintf(stderr, "Usage: %s [ -h | -c | -d ] [ -i <input file> ] [ -o <output file> ] [ -k <key file> ]\n", prog);
    fprintf(stderr, "Crypt and decrypt file by XXTEA cipher. Input file is padded to 512B boundary.\n");
    fprintf(stderr, "Key file must contain exactly 32 hexadecimal characters.\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "* Crypt file in.bin to file out.bin with key file key.txt:\n");
    fprintf(stderr, "  $ %s -c -i in.bin -o out.bin -k key.txt\n", prog);
    fprintf(stderr, "* Decrypt file in.bin to file out.bin with key file key.txt:\n");
    fprintf(stderr, "  $ %s -d -i in.bin -o out.bin -k key.txt\n", prog);
    
    return 0;
}

int print_opterr(int opt)
{
    fprintf(stderr, "Invalid option: %c\n", opt);
    return 1;
}

int read_key(char *keyfile, uint32_t *key)
{
    char s_key [33];
    char s_part_0 [9];
    char s_part_1 [9];
    char s_part_2 [9];
    char s_part_3 [9];
    FILE * f;

    f = fopen (keyfile, "r");
    if(f == NULL) {
        fprintf(stderr, "No key file '%s' found.\n", keyfile);
        return 1;
    }
    
    if ((fgets(s_key, 33, f) != NULL) && strlen(s_key) == 32)
    {
        strncpy(s_part_0, s_key, 8);
        s_part_0[8] = '\0';
        key[0] = strtoul(s_part_0, NULL, 16);
        
        strncpy(s_part_1, &(s_key[8]), 8);
        s_part_1[8] = '\0';
        key[1] = strtoul(s_part_1, NULL, 16);
        
        strncpy(s_part_2, &(s_key[16]), 8);
        s_part_2[8] = '\0';
        key[2] = strtoul(s_part_2, NULL, 16);
        
        strncpy(s_part_3, &(s_key[24]), 8);
        s_part_3[8] = '\0';
        key[3] = strtoul(s_part_3, NULL, 16);
        
        fclose(f);
        return 0;
    }
    else
    {
        fprintf(stderr, "Key file '%s' is not a valid key.\n", keyfile);
        fclose(f);
        return 1;
    }
    return 1;
}

int crypt_file(char *infile, char *outfile, char *keyfile)
{
    FILE * f;
    FILE * of;
    uint32_t key[4] = {0,0,0,0};
    uint8_t block[512];
    int size;
    int last = 0;
    
    if (read_key(keyfile, key) != 0)
    {
        return 1;
    }
    
    f = fopen (infile, "rb");
    if(f == NULL) {
        fprintf(stderr, "No input file '%s' found.\n", infile);
        return 1;
    }
    
    of = fopen (outfile, "wb");
    if(of == NULL) {
        fprintf(stderr, "Output file '%s' can't be created.\n", outfile);
        fclose(f);
        return 1;
    }
    
    while ((size = fread(block, sizeof(uint8_t), 512, f)) == 512 || (size > 0 && feof(f) && !last))
    {
        int i = 0;
        for (i = size; i < 512; i++)
        {
            block[i] = '0';
        }
        
        crypt((uint32_t *)block, 128, key);
        
        if (size < 512)
        {
            last = 1;
        }
        
        size = fwrite(block, sizeof(uint8_t), 512, of);
        if (size < 512)
        {
            fprintf(stderr, "Error while writing into '%s'.\n", outfile);
            fclose(f);
            fclose(of);
            return 1;
        }        
    }
    
    fclose(f);
    fclose(of);
    return 0;
}

int decrypt_file(char *infile, char *outfile, char *keyfile)
{
    FILE * f;
    FILE * of;
    uint32_t key[4] = {0,0,0,0};
    uint8_t block[512];
    int size;
    
    if (read_key(keyfile, key) != 0)
    {
        return 1;
    }
    
    f = fopen (infile, "rb");
    if(f == NULL) {
        fprintf(stderr, "No input file '%s' found.\n", infile);
        return 1;
    }
    
    of = fopen (outfile, "wb");
    if(of == NULL) {
        fprintf(stderr, "Output file '%s' can't be created.\n", outfile);
        fclose(f);
        return 1;
    }
    
    while ((size = fread(block, sizeof(uint8_t), 512, f)) == 512 )
    {      
        decrypt((uint32_t *)block, 128, key);
                
        size = fwrite(block, sizeof(uint8_t), 512, of);
        if (size < 512)
        {
            fprintf(stderr, "Error while writing into '%s'.\n", outfile);
            fclose(f);
            fclose(of);
            return 1;
        }        
    }
    
    fclose(f);
    fclose(of);
    return 0;
}

int print_error(char * msg, char * prog)
{
    fprintf(stderr, "%s: %s\n", prog, msg);
    return 1;
}

int main(int argc, char **argv)
{
    // action to be performed
    int crypt_valid   = 0;
    int decrypt_valid = 0;
    
    // name of the input file
    char *infile     = NULL;
    int infile_valid = 0;
    
    // name of the output file
    char *outfile     = NULL;
    int outfile_valid = 0;
    
    // name of the key file
    char *keyfile     = NULL;
    int keyfile_valid = 0;
    
    int opt;
    opterr = 0;
    
    while((opt = getopt(argc, argv, "hcdi:o:k:")) != -1) 
    {
        switch(opt) 
        {
            case 'h':
                return print_help(argv[0]);
            
            case 'c':
                crypt_valid = 1;
                break;
                
            case 'd':
                decrypt_valid = 1;
                break;

            case 'i':
                infile = optarg;
                infile_valid = 1;
                break;
                
            case 'o':
                outfile = optarg;
                outfile_valid = 1;
                break;
                
            case 'k':
                keyfile = optarg;
                keyfile_valid = 1;
                break;
                
            case '?':
            default:
                return print_opterr(optopt);
        }
    }
    
    if (crypt_valid && decrypt_valid)
    {
        return print_error("Use only option -c or -d, not both of them.", argv[0]);
    }
    
    if (!(crypt_valid || decrypt_valid))
    {
        return print_error("Option -c or -d must be used.", argv[0]);
    }
    
    if (!infile_valid)
    {
        return print_error("Input file must be specified.", argv[0]);
    }
    
    if (!outfile_valid)
    {
        return print_error("Output file must be specified.", argv[0]);
    }
    
    if (!keyfile_valid)
    {
        return print_error("Key file must be specified.", argv[0]);
    }
    
    
    if (crypt_valid)
    {
        return crypt_file(infile, outfile, keyfile);
    }
    
    if (decrypt_valid)
    {
        return decrypt_file(infile, outfile, keyfile);
    }
    
    return 1;
}
