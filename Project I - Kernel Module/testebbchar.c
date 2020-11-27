/**
 * @file   testebbchar.c
 * @author Derek Molloy _ Amirhossein Kargaran
 * @version 0.1
 * @brief  A Linux user space program that communicates with the ebbchar.c LKM. It passes a
 * string to the LKM and reads the response from the LKM. 
 * @see http://www.derekmolloy.ie/ and https://www.programiz.com/c-programming/c-file-input-output for a full description and follow-up descriptions.
*/
#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>

#define BUFFER_LENGTH 24                ///< The buffer length (crude but fine)
static char receive[BUFFER_LENGTH];     ///< The receive buffer from the LKM

int main(){
   int ret, fd;
   FILE *fptr;
   char stringToSend[BUFFER_LENGTH];
   fd = open("/dev/ebbchar", O_RDWR);             // Open the device with read/write access
   if (fd < 0){
      perror("failed to open");
      return errno;
   }

   fptr = fopen("filter.csv","r");
   while(!feof(fptr))
   {
	fgets(stringToSend,BUFFER_LENGTH,fptr);
	ret = write(fd, stringToSend, strlen(stringToSend)); // Send the string to the LKM
	if (ret < 0){
		perror("failed to write the message");
		return errno;
   	}
   }
   return 0;
}
