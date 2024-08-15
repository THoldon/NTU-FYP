/*
  New Custom Mutator for AFL++
  Written by Khaled Yakdan <yakdan@code-intelligence.de>
             Andrea Fioraldi <andreafioraldi@gmail.com>
             Shengtuo Hu <h1994st@gmail.com>
             Dominik Maier <mail@dmnk.co>
*/

// You need to use -I/path/to/AFLplusplus/include -I.
#include "afl-fuzz.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define DATA_SIZE (100)

static const char *commands[] = {

    "GET",
    "PUT",
    "DEL",

};

typedef struct my_mutator {

  afl_state_t *afl;

  // any additional data here!
  //size_t trim_size_current;
  //int    trimmming_steps;
  //int    cur_step;

  //u8 *mutated_out, *post_process_buf, *trim_buf;

} my_mutator_t;

/**
 * Initialize this custom mutator
 *
 * @param[in] afl a pointer to the internal state object. Can be ignored for
 * now.
 * @param[in] seed A seed for this mutator - the same seed should always mutate
 * in the same way.
 * @return Pointer to the data object this custom mutator instance should use.
 *         There may be multiple instances of this mutator in one afl-fuzz run!
 *         Return NULL on error.
 */
my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  srand(seed);  // needed also by surgical_havoc_mutate()

  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {

    perror("afl_custom_init alloc");
    return NULL;

  }

  /*if ((data->mutated_out = (u8 *)malloc(MAX_FILE)) == NULL) {

    perror("afl_custom_init malloc");
    return NULL;

  }

  if ((data->post_process_buf = (u8 *)malloc(MAX_FILE)) == NULL) {

    perror("afl_custom_init malloc");
    return NULL;

  }

  if ((data->trim_buf = (u8 *)malloc(MAX_FILE)) == NULL) {

    perror("afl_custom_init malloc");
    return NULL;

  }*/

  data->afl = afl;
	printf("in init\n");
  return data;

}

/**
 * Perform custom mutations on a given input
 *
 * (Optional for now. Required in the future)
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @param[in] buf Pointer to input data to be mutated
 * @param[in] buf_size Size of input data
 * @param[out] out_buf the buffer we will work on. we can reuse *buf. NULL on
 * error.
 * @param[in] add_buf Buffer containing the additional test case
 * @param[in] add_buf_size Size of the additional test case
 * @param[in] max_size Maximum size of the mutated output. The mutation must not
 *     produce data larger than max_size.
 * @return Size of the mutated output.
 */
size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf,
                       size_t add_buf_size,  // add_buf can be NULL
                       size_t max_size) {
	
	printf("in custom fuzz\n");
	
	for(int i=0;i<buf_size;i++){
                printf("%c",*(buf+i));
        }
        printf("\n");
	printf("*out_buf %x\n",*out_buf);
	printf("out_buf %x",out_buf);


  // Make sure that the packet size does not exceed the maximum size expected by
  // the fuzzer
  //size_t mutated_size = DATA_SIZE <= max_size ? DATA_SIZE : max_size;

  //memcpy(data->mutated_out, buf, buf_size);

  // Randomly select a command string to add as a header to the packet
  //memcpy(data->mutated_out, commands[rand() % 3], 3);

  //if (mutated_size > max_size) { mutated_size = max_size; }

  //*out_buf = data->mutated_out;
  //return mutated_size;
  return 0;

}


/**
 * Deinitialize everything
 *
 * @param data The data ptr from afl_custom_init
 */
void afl_custom_deinit(my_mutator_t *data) {

  /*free(data->post_process_buf);
  free(data->mutated_out);
  free(data->trim_buf);*/
  free(data);

}

void test(){
	printf("test function\n");
}

int main(){
	char post[] = "POST /wizsetup.htm HTTP/1.1\r\n"
			"Host: 172.21.0.2\r\n"
			"User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko\r\n"
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8\r\n"
			"Accept-Language: en-US,en;q=0.5\r\n"
			"Accept-Encoding: gzip, deflate\r\n"
			"Content-Type: application/x-www-form-urlencoded\r\n"
			"Content-Length: 57\r\n"
			"Origin: http://172.21.0.2\r\n"
			"Authorization: Digest username:\"admin\", realm=\"_00\", nonce=\"53521d96754a74aa4697a51e27507049\", uri=\"/wizsetup.htm\", response=\"cda52e6f640559a036a572eadbc9ca3e\", qop=auth, nc=00000010, cnonce=\"fb822d676d644d81\"\r\n"
			"Connection: keep-alive\r\n"
			"Referer: http://172.21.0.2/wizard.htm\r\n"
			"Upgrade-Insecure-Requests: 1\r\n"
			"Priority: u=0, i\r\n"
			"\r\n"
			"ReplySuccessPage=wizsetup.htm&ReplyErrorPage=wizsetup.htm";
	int i = 0;
	uint8_t *post_addr = &post; //buf
	size_t post_size = strlen(post); //buf_size
	/*printf("post_size: %i\n",post_size);
	
	for(i=0;i<strlen(post);i++){
		printf("%c",post[i]);
	}
	printf("\n");
	
	for(i=0;i<post_size;i++){
                printf("%c",*(ptr_addr+i));
        }
	printf("\n");*/
	
	afl_state_t *html_afl; //for init
	my_mutator_t *html_mutator = afl_custom_init(html_afl,0); //init mutator
	char mutated_post[] = ""; //out buf
	u8 *mutated_ptr = &mutated_post;
	u8 **mutated_d_ptr = &mutated_ptr; //out buf double pointer
	//*(*mutated_d_ptr+i)
	size_t mutated_size = afl_custom_fuzz(html_mutator,post_addr,post_size,mutated_d_ptr,NULL,NULL,9999999999);	

}
