/** \file
 * \brief Application code for SOEM/Ethercat test bench
 *
 */

 /* Merging of Npcap library examples with SOEM library
 Npcap discovers the compatible interfaces and SOEM runs on one of them.*/


/*	INCLUDES */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "ethercat.h"
#include <pcap.h>
#include <Windows.h>
#include <time.h>
#include "misc.h" 

/*	DEFINES	*/
#define EC_TIMEOUTMON 500
#define stack64k (64 * 1024)
#define print_num 100000 
#define PRINT_OUT 

/*	Variable declarations	*/
long NSEC_PER_SEC = 1000000000i64;
struct timeval tv;
int dorun = 0;
int deltat, tmax =0;
long toff;
long long gl_delta;
int DCdiff;
int os;
uint8 ob;
uint16 ob2;
uint8 *digout = 0;
char IOmap[4096];
OSAL_THREAD_HANDLE thread1, thread2, thread3;
int expectedWKC;
boolean needlf;
volatile int globalWkc;
boolean inOP;
uint8 currentgroup = 0;
int32 outData,inData;
int cycleTime;
int64 stream1[500000];
int64 stream2[500000];
int64 t1,t2;
int64 real_cycle;
int64 prev_real_cycle;
int64 jitt;
uint8 txbuf[128];
uint8 rxbuf[128];


/* pcap packet handler declaration*/
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


/* .csv file output function takes filename and length of tables as params
* can output 2 sets of data in current form
*/
int output_csv(char *fname, int length)
{
   FILE *fp;

   int  i;

   fp = fopen(fname, "w");
   if(fp == NULL)
      return 0;
   for (i = 0; i < length; i++)
   {
      fprintf(fp, "%d; %lld; %lld;\n", i, stream1[i], stream2[i]);
   }
   fclose(fp);

   return 1;
}


/*!
concatenation of slave inputs to an int for better printing and processing
\param slave slave number 
*/
int32 inPDO32(int slave)
{
	int32 res;
	uint32_t b0,b1,b2,b3;
	int slaveOffset = 0;
	/* calculate offest in IOmap based on slave number */
	if(slave > 1)
	{
		slaveOffset = (slave-1)*4;
	}
	b0 = ec_slave[0].inputs[3 + slaveOffset];
    b1 = ec_slave[0].inputs[2 + slaveOffset];
    b2 = ec_slave[0].inputs[1 + slaveOffset];
    b3 = ec_slave[0].inputs[0 + slaveOffset];

	res = b0 | b1 | b2 | b3 ;
	return res;
}

/* outputs changing function (for one cycle only)*/
void outPDO32(int slave, uint32_t data)
{
	int slaveOffset = 0;
	/* calculate offest in IOmap based on slave number */
	if(slave > 1)
	{
		slaveOffset = (slave-1)*4;
	}
	for (int i = 0 + slaveOffset; i < 3 + slaveOffset ;i++)
	{
		ec_slave[0].outputs[i]= (uint8_t)(outData >> (8*i));
	}
}

/* Mailbox handler attempt
no external protocol required

Returns 1 if success, 0 if failed*/
int mbxhandler(int slave, uint8_t *mbxDataIn, uint8_t *mbxDataOut)
{
	int mbxWkc = 0;
	ec_mbxbuft mbxIn, mbxOut;
	//uint32_t retval;
	/*check mbx state (new data? slave ack ?)*/
	if(ec_mbxreceive(slave, &mbxIn,EC_TIMEOUTRXM) < 1)
	{
		printf("Mailbox handling failed\n");
		return 0;
	}
	/*Ccheck if value is changed*/
	
	/*Clear mbx buffer*/
	ec_clearmbx(&mbxIn);

	/*Format and send data */
	uint16_t maxdata = ec_slave[slave].mbx_l - 0x10;
	if(*mbxDataIn < maxdata)
	{
		mbxWkc = ec_mbxsend(slave, &mbxOut,EC_TIMEOUTRXM);
		if(mbxWkc<1)
		{
			printf("Mailbox handling failed\n");
			return 0;
		}
	}

	/*Receive response*/




	return 1;

}


/* header creation function*/
void makeHeader(uint8_t *mbx, uint16_t length, int slave)
{
	uint16_t address = ec_slave[slave].configadr;
	uint8_t address_H = (uint8_t) (address >> 8);
	uint8_t address_L = (uint8_t) address;
	uint8_t length_H = (uint8_t) (length >> 8);
	uint8_t length_L = (uint8_t) length;
	uint8_t type = 0xF0;
	mbx[0] = length_H;
	mbx[1] = length_L;
	mbx[2] = address_H;
	mbx[3] = 0x00;
	mbx[4] = type;
}

OSAL_THREAD_FUNC mailbox_reader(void *lpParam)
{
   ecx_contextt *context = (ecx_contextt *)lpParam;
   int mbxWkc;
   ec_mbxbuft MbxIn;
   ec_mbxheadert * MbxHdr = (ec_mbxheadert *) MbxIn;


   //ec_mbxheadert * MbxHdr = (ec_mbxheadert *) MbxIn;

//    MbxHdr->address = ec_slave[1].aliasadr;
//    MbxHdr->length = 128 - 48;
//    MbxHdr->mbxtype = 0xF;
//    MbxHdr->priority = 0;
// 	MbxHdr = (ec_mbxheadert *) MbxIn;
// 	MbxHdr = (ec_mbxheadert *) txbuf;

   int ixme;
   //ec_setupheader(&txbuf);
   for (ixme = 5; ixme < sizeof(txbuf); ixme++)
   {
      txbuf[ixme] = ixme;
   }
   /* Send a made up frame to trigger a fragmented transfer
   * Used with a special bound impelmentaion of SOES. Will
   * trigger a fragmented transfer back of the same frame.
   */
  	makeHeader( txbuf, sizeof(txbuf) - 6, 1);
   mbxWkc = ecx_mbxsend(context, 1, (ec_mbxbuft *) txbuf, EC_TIMEOUTRXM );
	if(mbxWkc < 1)
	{
		printf("Error mbxWkc = %d\n", mbxWkc);
	}
	osal_usleep(1 * 1000 * 1000);
	 mbxWkc = ecx_mbxreceive(context, 1, (ec_mbxbuft *)&MbxIn, 0);
	  printf("Wkc : %d", mbxWkc);
	  for (int j = 0;  j < sizeof(MbxIn) ; j++)
	  {
		  printf("MbxIn[%d] = %x \n",j,MbxIn[j]);
	  }
//    for (;;)
//    {
//       /* Read mailbox if no other mailbox conversation is ongoing  eg. SDOwrite/SDOwrite etc.*/
	 
//       mbxWkc = ecx_mbxreceive(context, 1, (ec_mbxbuft *)&rxbuf, EC_TIMEOUTRXM);
// 	  printf("Wkc : %d", mbxWkc);
// 	  for (int j = 0;  j < sizeof(rxbuf) ; j++)
// 	  {
// 		  printf("MbxIn[%d] = %x \n",j,rxbuf[j]);
// 	  }
	  
// 	  printf("Mbx : %x, %x, %x\n", MbxIn[0], MbxIn[1], MbxIn[2]);
//       if (mbxWkc > 0)
//       {
//          printf("Unhandled mailbox response 0x%x\n", MbxHdr->mbxtype);
//       }
//       osal_usleep(1000 * 1000 * 1000);
// 	  //mbxWkc = ecx_mbxsend(context, 1, (ec_mbxbuft *) txbuf, EC_TIMEOUTRXM );
//  }
}

/* taken from simple_test example
Contains initialization of interface and slaves
Used to print IO and store them*/
void simpletest(char *ifname) //ifname name of interface
{
	int i, chk;
	needlf = FALSE;
	inOP = FALSE;

	printf("Starting... \n");

	/* initialise SOEM, bind socket to ifname */
	if (ec_init(ifname))
	{
		printf("ec_init on %s succeeded.\n", ifname);

		/* find and auto-config slaves */

		if (ec_config_init(FALSE) > 0)
		{

			printf("%d slaves found and configured.\n", ec_slavecount);
			
			ec_configdc(); // config distributed clocks
			
			for(i = 1; i<= ec_slavecount; i++)
			{
				printf("dcsync%d\n",i);
				ec_dcsync01(i,TRUE,cycleTime*1000,cycleTime*1000,0);
			// 	ec_dcsync0(i,TRUE,cycleTime,0);
			}
			
			ec_config_map(&IOmap); //configuration of the IO Map of devices

			

			
			printf("Slaves mapped, state to SAFE_OP.\n");

			/* wait for all slaves to reach SAFE_OP state */
			ec_statecheck(0, EC_STATE_SAFE_OP, EC_TIMEOUTSTATE * 4);
			
			/*launch mailbox handler thread*/
			osal_thread_create(&thread3, 128000, &mailbox_reader, &ecx_context);

			/* Print number of segments/branches in network*/

			printf("segments : %d : %d %d %d %d\n", ec_group[0].nsegments, ec_group[0].IOsegment[0], ec_group[0].IOsegment[1], ec_group[0].IOsegment[2], ec_group[0].IOsegment[3]);

			printf("Request operational state for all slaves\n");
			expectedWKC = (ec_group[0].outputsWKC * 2) + ec_group[0].inputsWKC; // wkc = 2*outputs + inputs ex : si 2 slaves -> 2 outputs *2 + 2inputs = 6
			printf("Calculated workcounter %d\n", expectedWKC);
			ec_slave[0].state = EC_STATE_OPERATIONAL;
			/* send one valid process data to make outputs in slaves happy*/
			ec_send_processdata();								 // sending processdata makes slaves go from preop to safeop
			int TimeOut = ec_receive_processdata(EC_TIMEOUTRET); // 
			/* request OP state for all slaves */
			ec_writestate(0);
			chk = 2000;


			/* wait for all slaves to reach OP state */
			do
			{
				ec_send_processdata();
				ec_receive_processdata(EC_TIMEOUTRET);
				ec_statecheck(0, EC_STATE_OPERATIONAL, 50000);
			} while (chk-- || (ec_slave[0].state != EC_STATE_OPERATIONAL));

			/*launch RT thread*/
			dorun = 1;

			if (ec_slave[0].state == EC_STATE_OPERATIONAL)
			{
				printf("Operational state reached for all slaves.\n");
				inOP = TRUE; //Bool for OP status
				
				/* cyclic loop */
				long long startTime = ec_DCtime; // approx. start time of cyclic communication (not used anymore)

				printf("Communication in progress ...\n");					   
				// Can calculate communication time ~= print_num * 2ms
				// for (i = 1; i <= print_num; i++)
				while(1)
				{	

					// change output on input change
					if(inPDO32(1) != inData)
					{
						outData++;
					}

					// refresh input value for next loop
					inData = inPDO32(1);


					#ifdef PRINT_OUT
						int j;
               			printf("Processdata cycle %5d , Wck %2d, DCtime %12lld, ct %9lld, Jitter %9lld, O:",
                  		dorun, globalWkc , ec_DCtime, real_cycle,jitt);

						/*jitter calculation*/
						jitt = real_cycle - prev_real_cycle;
						prev_real_cycle = real_cycle;

						/* printing master outputs*/
						for (j = ec_slave[0].Obytes-1; j >= 0; j--)
						{
							printf(" %2.2x", ec_slave[0].outputs[j]); 
						}
						
						/*printing master inputs*/
						printf(" I:");
						for (j = ec_slave[0].Ibytes-1; j >= 0; j--)
						{
							printf(" %2.2x", ec_slave[0].inputs[j]); 
						}
						//printf(" T(ns):%" PRId64 "", ec_DCtime - startTime);
						//printf(" Slave cycle time : %I32d ", ec_slave[1].DCcycle);
						//printf(" Cycle time (ns): %I64d Com time %I64d", (ec_DCtime - startTime) / dorun, (ec_DCtime - startTime));
						printf("\r");
					#endif
						needlf = TRUE;
						fflush(stdout);
					/* sleep time to not overload CPU*/
					osal_usleep(1000000);
				}
				dorun = 0;
				inOP = FALSE;
			}
			else
			{	
				/*return error if slaves not in OP*/
				printf("Not all slaves reached operational state.\n");
				ec_readstate();
				for (i = 1; i <= ec_slavecount; i++)
				{
					if (ec_slave[i].state != EC_STATE_OPERATIONAL)
					{
						printf("Slave %d State=0x%2.2x StatusCode=0x%4.4x : %s\n",i,  ec_slave[i].state, ec_slave[i].ALstatuscode, ec_ALstatuscode2string(ec_slave[i].ALstatuscode));
					}
				}
			}
			printf("\nRequest init state for all slaves\n");
			ec_slave[0].state = EC_STATE_INIT;
			/* request INIT state for all slaves */
			ec_writestate(0);
		}
		else
		{
			printf("No slaves found!\n");
		}
		printf("End SOEM close socket\n");
		/* stop SOEM, close socket */
		ec_close();
		/* file output*/
		output_csv("outputs.csv",print_num);
	}
	else
	{
		printf("No socket connection on %s\nExecute as root\n", ifname);
	}
}

/* add ns to timespec */
void add_timespec(struct timespec *ts, long addtime)
{
   long  sec, nsec;

   nsec = addtime % NSEC_PER_SEC;
   sec = (addtime - nsec) / NSEC_PER_SEC;
   ts->tv_sec += sec;
   ts->tv_nsec += nsec;
   if ( ts->tv_nsec > NSEC_PER_SEC )
   {
      nsec = ts->tv_nsec % NSEC_PER_SEC;
      ts->tv_sec += (ts->tv_nsec - nsec) / NSEC_PER_SEC;
      ts->tv_nsec = nsec;
   }
}

/* PI calculation to get linux time synced to DC time */
void ec_sync(long long reftime, long cycletime , long *offsettime)
{
   static long  integral = 0;
   long  delta;
   /* set linux sync point 500us later than DC sync, just as example */
   delta = (reftime - 500000) % cycletime;
   if(delta> (cycletime / 2)) { delta= delta - cycletime; }
   if(delta>0){ integral++; }
   if(delta<0){ integral--; }
   *offsettime = -(delta / 100) - (integral / 20); // offsettime = - (delta*P) - (integral*I)
   gl_delta = delta;
}

/* not used port of nanosleep function from Linux*/
static void  nanosleep (struct timespec *requested_delay)  
{  
      time_t seconds = requested_delay->tv_sec; // second part   
      long int nanoSeconds = requested_delay->tv_nsec; // nano seconds part  
  if (seconds > 0) 
  {
	DWORD msec = (DWORD) seconds * 1000 + nanoSeconds /  1000000i64;
  	Sleep (msec); //If more than one second  
  }
  else  
   {     
    static double frequency; // ticks per second  
    if (frequency == 0)  
     {  
      LARGE_INTEGER freq;  
      if (!QueryPerformanceFrequency (&freq))  
       {  
        /* Cannot use QueryPerformanceCounter. */
        Sleep (nanoSeconds / 1000000);  
        return;  
       }  
      frequency = (double) freq.QuadPart / 1000000000.0;     // ticks per nanosecond  
     }  
    double counter_difference = nanoSeconds * frequency;  
    int sleep_part = (int) nanoSeconds / 1000000 - 10;  
    LARGE_INTEGER start;  
    QueryPerformanceCounter (&start);  
    long long expected_counter = start.QuadPart + (long) counter_difference;  
    if (sleep_part > 0)     // for milliseconds part  
     Sleep(sleep_part);  
	 LARGE_INTEGER stop;  
    do                         // for nanoseconds part  
     {  
      QueryPerformanceCounter (&stop);  
      printf("Boucle ********");
	
     }  while (!(stop.QuadPart >= expected_counter));
   }  
 } 

/*port of clock_gettime func on win*/
int clock_gettime( struct timespec *spec)     
{  
	spec->tv_nsec = osal_current_time().usec * 1000;
	return 0;
}

/* RT EtherCAT thread */
OSAL_THREAD_FUNC_RT ecatthread(void *ptr)
{
   	
	struct timespec   ts; 
	//struct timespec tleft;
   	int ht;
	long cycletime;
   	clock_gettime(&ts);
   	ht = (ts.tv_nsec / 1000000) + 1; /* round to nearest ms */
   	ts.tv_nsec = ht * 1000000;
   	cycletime = *(int*)ptr * 1000; /* cycletime in ns */
   	toff = 0;
   	dorun = 0;
   	ec_send_processdata();
   	while(1)
   	{
      /* calculate next cycle start */
      // add_timespec(&ts, cycletime + toff);
      /* wait to cycle start */
	 //printf("nanosecond wait : %d\n",cycletime + toff);
     //   do
	 //   {
	 // 	  clock_gettime(&tleft);
	 //   }
	 //   while(!(tleft.tv_nsec >= ts.tv_nsec));

	  osal_usleep((cycletime + toff)/ 1000);
      if (dorun>0)
      {
         globalWkc = ec_receive_processdata(EC_TIMEOUTRET);
		 
		t1 = ec_DCtime;
		real_cycle = t1-t2;
		t2 = ec_DCtime;
		 if(dorun < sizeof(stream1))
		 {
			stream1[dorun] = real_cycle;
			stream2[dorun] = toff;
		 }

         dorun++;
         /* if we have some digital output, cycle */
         //if( digout ) *digout = (uint8) ((dorun / 16) & 0xff);
		outPDO32(1,outData);
		outPDO32(2,outData);
		outPDO32(3,outData);
		outPDO32(4,outData);
         if (ec_slave[0].hasdc)
         {
            /* calulate toff to get linux time and DC synced */
            ec_sync(ec_DCtime, cycletime, &toff);
         }
         ec_send_processdata();
      }
   }
}


/* OS abstracted thread to manage errors */
OSAL_THREAD_FUNC ecatcheck(void *ptr)
{
	int slave;
	(void)ptr; /* Not used */

	while (1)
	{
		if (inOP && ((globalWkc < expectedWKC) || ec_group[currentgroup].docheckstate))
		{
			printf("Expected %d and got %d ", expectedWKC,globalWkc);
			if (needlf)
			{
				needlf = FALSE;
			}
			/* one ore more slaves are not responding */
			ec_group[currentgroup].docheckstate = FALSE;
			ec_readstate();
			for (slave = 1; slave <= ec_slavecount; slave++)
			{
				if ((ec_slave[slave].group == currentgroup) && (ec_slave[slave].state != EC_STATE_OPERATIONAL))
				{
					ec_group[currentgroup].docheckstate = TRUE;
					if (ec_slave[slave].state == (EC_STATE_SAFE_OP + EC_STATE_ERROR))
					{
						printf("ERROR : slave %d is in SAFE_OP + ERROR, attempting ack.\n", slave);
						ec_slave[slave].state = (EC_STATE_SAFE_OP + EC_STATE_ACK);
						ec_writestate(slave);
					}
					else if (ec_slave[slave].state == EC_STATE_SAFE_OP)
					{
						printf("WARNING : slave %d is in SAFE_OP, change to OPERATIONAL.\n", slave);
						ec_slave[slave].state = EC_STATE_OPERATIONAL;
						ec_writestate(slave);
					}
					else if (ec_slave[slave].state > EC_STATE_NONE)
					{
						if (ec_reconfig_slave(slave, EC_TIMEOUTMON))
						{
							ec_slave[slave].islost = FALSE;
							printf("MESSAGE : slave %d reconfigured\n", slave);
						}
					}
					else if (!ec_slave[slave].islost)
					{
						/* re-check state */
						ec_statecheck(slave, EC_STATE_OPERATIONAL, EC_TIMEOUTRET);
						if (ec_slave[slave].state == EC_STATE_NONE)
						{
							ec_slave[slave].islost = TRUE;
							printf("ERROR : slave %d lost\n", slave);
						}
					}
				}
				if (ec_slave[slave].islost)
				{
					if (ec_slave[slave].state == EC_STATE_NONE)
					{
						if (ec_recover_slave(slave, EC_TIMEOUTMON))
						{
							ec_slave[slave].islost = FALSE;
							printf("MESSAGE : slave %d recovered\n", slave);
						}
					}
					else
					{
						ec_slave[slave].islost = FALSE;
						printf("MESSAGE : slave %d found\n", slave);
					}
				}
			}
			if (!ec_group[currentgroup].docheckstate)
				;
			printf("OK : all slaves resumed OPERATIONAL.\n");
		}
		osal_usleep(10000);
	}
}


/* main function*/
int main(int argc, char *argv[])
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	// pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	if (argc != 2 || atoi(argv[1]) < 100)
	{
		printf("Usage : app.exe [cycletime]\n Cycletime in microseconds > 100");
		return(0);
	}

	dorun = 0;
	cycleTime = atoi(argv[1]);

	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	/* if no interface found*/
	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return -1;
	}

	/* ask for user input*/
	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++)
		;

	printf("SOEM (Simple Open EtherCAT Master)\nTest app\n");

	/* create thread to handle slave error handling in OP */
	// pthread_create( &thread1, NULL, (void *) &ecatcheck, (void*) &cycleTime);
	osal_thread_create(&thread1, 128000, &ecatcheck, (void *)&ctime);
	/* create RT thread */
    osal_thread_create_rt(&thread2, stack64k * 2, &ecatthread, (void*) &cycleTime);
	/* start cyclic part */
	simpletest(d->name);

	printf("End program\n");
	return (0);
}

/* Callback function invoked by libpcap for every incoming packet (not used yet)*/
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;

	/*
	 * unused variables
	 */
	(VOID)(param);
	(VOID)(pkt_data);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
}
