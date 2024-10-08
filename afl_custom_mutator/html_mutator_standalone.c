/*
  New Custom Mutator for AFL++
  Written by Khaled Yakdan <yakdan@code-intelligence.de>
             Andrea Fioraldi <andreafioraldi@gmail.com>
             Shengtuo Hu <h1994st@gmail.com>
             Dominik Maier <mail@dmnk.co>
*/

// You need to use -I/path/to/AFLplusplus/include -I.
#include "afl-fuzz.h"
#include "afl-mutations.h"

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

typedef struct http_fields {
	char *name;
	int start_byte;
	int end_byte;

} http_fields_t;

typedef struct my_mutator {

  afl_state_t *afl;
  //maybe place flags here for which fields to maintain

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

  srand(seed);

  //dummy variables so that it can run standalone	
  afl->queue_cycle = 1;
  afl->fsrv.dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (afl->fsrv.dev_urandom_fd < 0) { PFATAL("Unable to open /dev/urandom"); }
  rand_set_seed(afl,seed);


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

  return data;

}

char* get_input_name(char *input,unsigned int cur_start,unsigned int cur_end){ //get name of each header field
	int byte = 0;
	int pos = 0;
	for(byte=cur_start;byte<cur_end;byte++){
		if(*(input+byte) == 0x20){ //find the space character, every header has this after : or POST or GET
			char *field_name = malloc(pos+1);
			memcpy(field_name,input+cur_start,pos); //copy out the name
			field_name[pos] = '\0';
			return field_name; //return it
		}
		pos++;
	}
	return NULL;
}

http_fields_t *get_input_fields(char *input, size_t buf_size,unsigned int *num_fields){ //split packet into each individual field

	http_fields_t *input_fields = calloc(1,sizeof(http_fields_t));
	unsigned int pos = 0;
	unsigned int cur_start = 0;
	unsigned int cur_end = 0;
	char fields_terminator[2] = {0x0D,0x0A}; //each field ends with 0x0D 0x0A
	char header_terminator[4] = {0x0D,0x0A,0x0D,0X0A}; //each header ends with 0x0D 0x0A 0x0D 0x0A

	while(pos<=buf_size){ //traverse through packet
		if((pos>=4) && (memcmp((input+pos-1),header_terminator,4)==0)){ //when header_terminator is reached
			(*num_fields)++; //increase number of fields
                        input_fields = (http_fields_t *)realloc(input_fields, *num_fields*sizeof(http_fields_t)); //set more memory for input_fields array
			cur_end += 2; //account for another 0x0d 0x0a
                        input_fields[*num_fields-1].start_byte = cur_start; //get start byte
                        input_fields[*num_fields-1].end_byte = cur_end; //get end byte
                        input_fields[*num_fields-1].name = get_input_name(input,cur_start,cur_end); //get name of field

                        cur_start = cur_end + 1; //move cur_start to start of next field
                        cur_end = cur_start; //move cur_end to not overlap

			(*num_fields)++; //increase number of fields
			input_fields = (http_fields_t *)realloc(input_fields, *num_fields*sizeof(http_fields_t)); //set more memory for input_fields array
			input_fields[*num_fields-1].start_byte = cur_start; //start of body
			input_fields[*num_fields-1].end_byte = buf_size; //end of packet is end of body
			input_fields[*num_fields-1].name = "BODY"; //body has no name so give it one
			break; //end of packet reached


		}


		else if((pos>=2) && (memcmp((input+pos-1),fields_terminator,2)==0)){ //when field_terminator is reached
			(*num_fields)++; //increase number of fields
			input_fields = (http_fields_t *)realloc(input_fields, *num_fields*sizeof(http_fields_t)); //set more memory for input_fields array
			input_fields[*num_fields-1].start_byte = cur_start; //get start byte
			input_fields[*num_fields-1].end_byte = cur_end; //get end byte
			input_fields[*num_fields-1].name = get_input_name(input,cur_start,cur_end); //get name of field

			/*int i = 0; //check if range is correct
			for(i = 0;i<=cur_end-cur_start;i++)
				printf("%x ",*(input+i));*/

			cur_start = cur_end + 1; //move cur_start to start of next field
			cur_end = cur_start; //move cur_end to not overlap
			pos++; //get to next byte in input

			/*printf("start_byte %i\n",input_fields[*num_fields-1].start_byte); //check if bytes saved correctly
			printf("end_byte %i\n", input_fields[*num_fields-1].end_byte);
			printf("end char %x\n",*(input+cur_start-1));*/

		}
		else{
			pos++; //move one byte forward
			cur_end++; //move end byte one byte forward
		}


	}
	
	int i = 0;
	/*for(i=0;i<*num_fields;i++){ //check if fields saved correctly
		printf("field number %i\n",i);
		printf("start_byte: %i\n",input_fields[i].start_byte);
		printf("end_byte:%i\n",input_fields[i].end_byte);
		int j = 0;
		for(j=input_fields[i].start_byte;j<=input_fields[i].end_byte;j++){ //check if bytes within range are correct
			printf("%x ",*(input+j));
		}
		printf("\n");
	}*/
	return input_fields;

}

void split_fields(char* local_input,char** to_mutate, char** to_maintain,char** body_to_mutate,http_fields_t* input_fields,unsigned int *num_fields){ //split packet into fields to maintain and 
																		      //fields to mutate

	int i = 0;

	char *maintain_names[] = {"POST","Host:","Authorization:","Referer:","Content-Length:","Cookie:"}; //fields to not mutate
	int maintain_offset = 0; //for to_maintain memcpy later
	int mutate_offset = 0; //for to_mutate memcpy later
	int body_size = 0;

	for(i=0;i<*num_fields;i++){ //go through each field
		bool maintain_set = false; //boolean to check if maintain field was reached
		int j = 0;
		if(strcmp(input_fields[i].name, "Content-Length:") == 0) //skip content-length since its value has to adapt to body, append to the full packet last
			continue;
		int field_size = input_fields[i].end_byte - input_fields[i].start_byte + 1; //get size of field to copy

		if(strcmp(input_fields[i].name, "BODY") == 0){ //if body reached
			*body_to_mutate = malloc(field_size);
			memcpy(*body_to_mutate,local_input+input_fields[i].start_byte,field_size); //save out body
			continue;
                }

		//while(maintain_names[j]){ //scan through array of fields to maintain
		while(j<6){
			if(strcmp(maintain_names[j], input_fields[i].name) == 0){ //check if current field is a field to maintain
				if(maintain_offset == 0){ //if first field to be maintained
					*to_maintain = malloc(field_size); //allocate necessary size
					memcpy(*to_maintain,local_input+input_fields[i].start_byte,field_size); //copy in field's text
				}
				else{
					*to_maintain = realloc(*to_maintain, (maintain_offset + field_size)); //allocate more space to_maintain to append
					memcpy(*to_maintain + maintain_offset,local_input + input_fields[i].start_byte,field_size); //copy in field's text
				}
				maintain_offset += field_size; //increase maintain offset to adjust where to copy
				maintain_set = true;
				break;
			}
			j++;
		}
		
		if(maintain_set == false){ //if field is not to be maintained
			//printf("\nto_mutate\n");
			if(mutate_offset == 0){ //if first field to be mutated
				*to_mutate = malloc(field_size); //allocate necessary size
				memcpy(*to_mutate,local_input+input_fields[i].start_byte,field_size); //copy in field's text
			}
			else{
				*to_mutate = realloc(*to_mutate, (mutate_offset+field_size)); //allocate more space to to_mutate to append
				memcpy(*to_mutate + mutate_offset ,local_input+input_fields[i].start_byte,field_size); //copy in field's text
			}
			/*for(int j = 0;j<field_size;j++){
                                printf("%c",*(local_input+input_fields[i].start_byte+j));
                        }
                        for(int j = 0;j<field_size;j++){
                                printf("%x ",*(local_input+input_fields[i].start_byte+j));
                        }*/

			mutate_offset += field_size; //increase mutate offset to adjust where to copy
		}

	}

	*body_to_mutate = realloc(*body_to_mutate,(body_size+1));
	(*body_to_mutate)[body_size] = '\0';
	/*for(int i = 0;i<body_size;i++){
		printf("%x ",(*body_to_mutate)[i]);
	}*/


	*to_maintain = realloc(*to_maintain,(maintain_offset+1));
	//printf("\nto_maintain\n");
	/*for(int i = 0;i<maintain_offset;i++){
		printf("%c",(*to_maintain)[i]);
	}
	printf("\n");
	for(int i =0;i<maintain_offset+1;i++){
		printf("%x ",(*to_maintain)[i]);
	}*/

	*to_mutate = realloc(*to_mutate,(mutate_offset+1));
	(*to_maintain)[maintain_offset] = '\0';
	(*to_mutate)[mutate_offset] = '\0';
	/*for(int i = 0;i<mutate_offset;i++){
		printf("%c",(*to_mutate)[i]);
	}
	for(int i = 0;i<mutate_offset;i++){
		printf("%x ",(*to_mutate)[i]);
	}*/
	return;

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


	unsigned int *num_fields = 0;
	char *local_input = NULL;
	local_input = malloc(buf_size+1); //store input buffer on local variable to work on
	memcpy(local_input,buf,buf_size);
	local_input[buf_size] = '\0';
	http_fields_t *input_fields = get_input_fields(local_input,buf_size,&num_fields);//find out all fields present in packet
	int i = 0;

	char *to_mutate = NULL; //header fields to mutate
	char *to_maintain = NULL; //header fields to maintain
	char *body_to_mutate = NULL;//body to mutate

	split_fields(local_input,&to_mutate,&to_maintain,&body_to_mutate,input_fields,&num_fields); //split fields into their respective arrays

	u32 to_maintain_len = strlen(to_maintain); //get length of header fields to maintain
	u32 pre_to_mutate_len = strlen(to_mutate); //get length of header fields to mutate
	u32 pre_body_to_mutate_len = strlen(body_to_mutate); //get length of body to mutate
	u32 havoc_steps = 1 + rand_below(data->afl,16); //set up havoc
	
	/*printf("header unmutaed\n"); //check fields to be mutated before mutation
	for(i=0;i<pre_to_mutate_len;i++){
		printf("%c",to_mutate[i]);
	}*/

	char *dummy_malloc = malloc(to_maintain_len); //need this malloc or it may crash with malloc(): corrupted top size
	free(dummy_malloc); //free it immediately to not waste memory
	
	u32 post_to_mutate_len = afl_mutate(data->afl, to_mutate, pre_to_mutate_len, havoc_steps,true,true,add_buf,add_buf_size,max_size); //mutate header fields
	
	/*printf("\nheader mutated\n"); //check fields to be mutated after mutation
	for(i=0;i<post_to_mutate_len;i++){
		printf("%c",to_mutate[i]);
	}*/

	/*printf("body unmutaed\n"); //check body before mutation
	for(i=0;i<pre_body_to_mutate_len;i++){
		printf("%x ",body_to_mutate[i]);
	}*/

	u32 post_body_to_mutate_len = afl_mutate(data->afl,body_to_mutate,pre_body_to_mutate_len,havoc_steps,true,true,add_buf,add_buf_size,max_size); //mutate body
	
	/*printf("\nbody mutated\n"); //check body after mutation
	for(i=0;i<post_body_to_mutate_len;i++){
		printf("%c",body_to_mutate[i]);
	}*/
	free(input_fields);
	char *content_length_field = "Content-Length: "; //adjust content length accordingly
	
	//calculate number of digits for body length
	int body_digits = 0; 
	int len_holder = post_body_to_mutate_len;

	while(len_holder>1){
		len_holder/=10;
		body_digits++;
	}

	int adjusted_content_length_len = strlen(content_length_field) + body_digits + 3; // account for /r/n
	//char *adjusted_content_length = NULL;
	char *adjusted_content_length = malloc(adjusted_content_length_len+1); //allocate memory depending on how many characters there are
	sprintf(adjusted_content_length,"%s%d\r\n",content_length_field,post_body_to_mutate_len); //concat them all together
	adjusted_content_length[adjusted_content_length_len] = '\0';
	/*printf("adjusted content length len %i\n",adjusted_content_length_len);
	for(int i = 0;i<adjusted_content_length_len;i++){ //check if content-length is put together correctly
		printf("%x ",adjusted_content_length[i]);
	}
	for(int i = 0;i<adjusted_content_length_len;i++){
		printf("%c",adjusted_content_length[i]);
	}*/

	//make sure to_mutate ends with \r\n\r\n and to_maintain ends with \r\n
	if(to_maintain[to_maintain_len-4] == '\r' && to_maintain[to_maintain_len-3] == '\n' && to_maintain[to_maintain_len-2] == '\r' && to_maintain[to_maintain_len-1] == '\n'){
		to_maintain = realloc(to_maintain,to_maintain_len-2);
		to_maintain_len -= 2;
	}
	if(!(to_mutate[post_to_mutate_len-4] == '\r' && to_mutate[post_to_mutate_len-3] == '\n' && to_mutate[post_to_mutate_len-2] == '\r' && to_mutate[post_to_mutate_len-1] == '\n')){
		to_mutate = realloc(to_mutate,post_to_mutate_len+2);
		post_to_mutate_len += 2;
		to_mutate[post_to_mutate_len-4] = '\r';
		to_mutate[post_to_mutate_len-3] = '\n';
		to_mutate[post_to_mutate_len-2] = '\r';
		to_mutate[post_to_mutate_len-1] = '\n';
	}

	char *mutated_packet = malloc(to_maintain_len + post_to_mutate_len + post_body_to_mutate_len + adjusted_content_length_len); //allocate memory for mutated packet
	int mutated_len = 0;
	memcpy(mutated_packet,to_maintain,to_maintain_len); //copy in fields maintained
	mutated_len += to_maintain_len; //keep track of packet length
	mutated_packet += to_maintain_len; //move pointer forward
	free(to_maintain);

	memcpy(mutated_packet,adjusted_content_length,adjusted_content_length_len); //copy in adjusted content length
	mutated_len += adjusted_content_length_len; //keep track of packet length
	mutated_packet += adjusted_content_length_len; //move pointer forward
	free(adjusted_content_length);

	memcpy(mutated_packet,to_mutate,post_to_mutate_len); //copy in fields mutated
	mutated_len += post_to_mutate_len; //keep track of packet length
	mutated_packet += post_to_mutate_len; //move pointer forward
	free(to_mutate);

	memcpy(mutated_packet,body_to_mutate,post_body_to_mutate_len); //copy in body mutated
	free(body_to_mutate);

	mutated_packet -= mutated_len; //move pointer back to start
	mutated_len += post_body_to_mutate_len; //keep track of packet length
	
	/*printf("\nmutated packet\n"); //check if mutated packet successfully assembled
	for(i=0;i<mutated_len;i++){
		printf("%c",mutated_packet[i]);
	}*/
	free(local_input);
	
	*out_buf = mutated_packet;
	return mutated_len;

}


/**
 * Deinitialize everything
 *
 * @param data The data ptr from afl_custom_init
 */
void afl_custom_deinit(my_mutator_t *data) {

  free(data);

}

//int main(){
	//char post[] = "POST /wizsetup.htm HTTP/1.1\r\n" //sample post packet
	//		"Host: 172.21.0.2\r\n"
	//		"User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko\r\n"
	//		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8\r\n"
	/*		"Accept-Language: en-US,en;q=0.5\r\n"
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
			"ReplySuccessPage=wizsetup.htm&ReplyErrorPage=wizsetup.htm";*/
	
	/*FILE *seed;
	seed = fopen("/home/ubuntu/FYP/NTU-FYP/seed_scraper/seed1","r");
	char *post;
	fseek(seed,0,SEEK_SET);
	post = calloc(770,1);
	fread(post,1,769,seed);
	printf("og post %s\n",post);

	int i = 0;
	uint8_t *post_addr = post; //buf
	size_t post_size = strlen(post); //buf_size

	afl_state_t *html_afl = calloc(1,sizeof(afl_state_t)); //for init
	
	my_mutator_t *html_mutator = afl_custom_init(html_afl,0); //init mutator
	unsigned char *mutated_post = NULL;
	size_t mutated_size = afl_custom_fuzz(html_mutator,post_addr,post_size,&mutated_post,NULL,NULL,769);
	
	printf("\n\nin main\n\n");
	for(i=0;i<mutated_size;i++){
		printf("%c",mutated_post[i]); //check mutation
	}
	printf("\n");
	for(i=0;i<mutated_size;i++){
		printf("%x ",mutated_post[i]);
	}

	afl_custom_deinit(html_mutator); //deinit custom mutator
}*/
