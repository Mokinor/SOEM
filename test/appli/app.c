/** \file
 * \brief Application code for SOEM/Ethercat test bench
 *
 */

 /* Merging of Npcap library examples with SOEM library
 Npcap discovers the compatible interfaces and SOEM runs on one of them.*/

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "ethercat.h"
#include <pcap.h>
#include <Windows.h>
#include <time.h>
#include "misc.h" /* LoadNpcapDlls */

#define EC_TIMEOUTMON 500
#define stack64k (64 * 1024)

long NSEC_PER_SEC = 1000000000i64;
struct timeval tv, t1, t2;
int dorun = 0;
int deltat, tmax = 0;
long toff;
long long gl_delta;
int DCdiff;
int os;
uint8 ob;
uint16 ob2;
uint8 *digout = 0;
char IOmap[4096];
OSAL_THREAD_HANDLE thread1, thread2;
int expectedWKC;
boolean needlf;
volatile int wkc;
boolean inOP;
uint8 currentgroup = 0;
int32 outData,inData;
int cycleTime;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int32 inPDO32(int slave)
{
	int32 res;
	uint32_t b0,b1,b2,b3;
	int slaveOffset = 0;
	if(slave > 1)
	{
		slaveOffset = slave*4;
	}
	b0 = ec_slave[0].inputs[3 + slaveOffset];
    b1 = ec_slave[0].inputs[2 + slaveOffset];
    b2 = ec_slave[0].inputs[1 + slaveOffset];
    b3 = ec_slave[0].inputs[0 + slaveOffset];

	res = b0 | b1 | b2 | b3 ;
	return res;
}

void outPDO32(int slave, uint32_t data)
{
	int slaveOffset = 0;
	if(slave > 1)
	{
		slaveOffset = slave*4;
	}
	for (int i = 0 + slaveOffset; i < 3 + slaveOffset ;i++)
	{
		ec_slave[0].outputs[i]= (uint8_t)(outData >> (8*i));
	}
}
// Simple test from SOEM library (calls all the useful functions)
void simpletest(char *ifname) //ifname name of interface
{
	int i, j, oloop, iloop, chk;
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

			ec_config_map(&IOmap); //configuration of the IO Map of devices

			ec_configdc(); // config distributed clocks

			ec_dcsync01(1,1,cycleTime,1,0);
			printf("Slaves mapped, state to SAFE_OP.\n");

			/* wait for all slaves to reach SAFE_OP state */
			ec_statecheck(0, EC_STATE_SAFE_OP, EC_TIMEOUTSTATE * 4);

			/* Value of input and output loops (limited to 8)*/

			oloop = ec_slave[0].Obytes;
			printf("oloop : %d\n", oloop);
			if ((oloop == 0) && (ec_slave[0].Obits > 0))
				oloop = 1;
			if (oloop > 8)
				oloop = 8;

			iloop = ec_slave[0].Ibytes;
			printf("iloop : %d\n", iloop);
			if ((iloop == 0) && (ec_slave[0].Ibits > 0))
				iloop = 1;
			if (iloop > 8)
				iloop = 8;

			/* Print number of segments/branches in network*/

			printf("segments : %d : %d %d %d %d\n", ec_group[0].nsegments, ec_group[0].IOsegment[0], ec_group[0].IOsegment[1], ec_group[0].IOsegment[2], ec_group[0].IOsegment[3]);

			printf("Request operational state for all slaves\n");
			expectedWKC = (ec_group[0].outputsWKC * 2) + ec_group[0].inputsWKC; // wkc = 2*outputs + inputs ex : si 2 slaves -> 2 outputs *2 + 2inputs = 6
			printf("Calculated workcounter %d\n", expectedWKC);
			ec_slave[0].state = EC_STATE_OPERATIONAL;
			/* send one valid process data to make outputs in slaves happy*/
			ec_send_processdata();								 // pas pour les rendre happy (passe les slaves de l'etat safe-op a op)
			int TimeOut = ec_receive_processdata(EC_TIMEOUTRET); // def wkc de transmission de PDO/PDI
			printf("TimeoutRet : %d\n", TimeOut);
			/* request OP state for all slaves */
			ec_writestate(0);
			chk = 200;


			/* wait for all slaves to reach OP state */
			do
			{
				ec_send_processdata();
				ec_receive_processdata(EC_TIMEOUTRET);
				ec_statecheck(0, EC_STATE_OPERATIONAL, 50000);
			} while (chk-- && (ec_slave[0].state != EC_STATE_OPERATIONAL));

			dorun = 1;

			if (ec_slave[0].state == EC_STATE_OPERATIONAL)
			{
				printf("Operational state reached for all slaves.\n");
				inOP = TRUE; //Bool for OP status
				
				/* cyclic loop */
				long long startTime = ec_DCtime; //enreg temps au départ de la com (eviter les temps inutilisables)
											   // reférence prise sur le temps affiché par les DCs
				for (i = 1; i <= 20000; i++)
				{	

					
					/*if(inPDO32(1) != inData)
					{
						outData++;
					}*/
					//outData++;
					inData = inPDO32(1);
					outPDO32(1,outData);

               			printf("Processdata cycle %5d , Wck %3d, DCtime %12lld, dt %12lld, O:",
                  		dorun, wkc , ec_DCtime, gl_delta);

						for (j = ec_slave[0].Obytes; j >= 0; j--)
						{
							printf(" %2.2x", ec_slave[0].outputs[j]); //printing outputs ?
						}

						printf(" I:");
						for (j = ec_slave[0].Ibytes; j >= 0; j--)
						{
							printf(" %2.2x", ec_slave[0].inputs[j]); //printing inputs ?
						}
						//printf(" T(ns):%" PRId64 "", ec_DCtime - startTime);
						//printf(" Slave cycle time : %I32d ", ec_slave[1].DCcycle);
						printf(" Cycle time (ns): %I64d Com time %I64d", (ec_DCtime - startTime) / dorun, (ec_DCtime - startTime));
						printf("\r");
						needlf = TRUE;
						fflush(stdout);
					
					osal_usleep(5000);
				}
				dorun = 0;
				inOP = FALSE;
			}
			else
			{
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
   /* set linux sync point 50us later than DC sync, just as example */
   delta = (reftime - 50000) % cycletime;
   if(delta> (cycletime / 2)) { delta= delta - cycletime; }
   if(delta>0){ integral++; }
   if(delta<0){ integral--; }
   *offsettime = -(delta / 100) - (integral / 20);
   gl_delta = delta;
}

/*port of clock_gettime func on win*/
int clock_gettime(int dummy, struct timespec *spec)     
{  
	__int64 wintime; 
	GetSystemTimeAsFileTime((FILETIME*)&wintime);
	wintime      -=116444736000000000i64;  //1jan1601 to 1jan1970
	spec->tv_sec  =wintime / 10000000i64;           //seconds
	spec->tv_nsec =wintime % 10000000i64 *100;      //nano-seconds
	return 0;
}

/* RT EtherCAT thread */
OSAL_THREAD_FUNC_RT ecatthread(void *ptr)
{
   	struct timespec   ts; 
	//struct timespec tleft;
   	int ht;
	long cycletime;

   	clock_gettime(0, &ts);
   	ht = (ts.tv_nsec / 1000000) + 1; /* round to nearest ms */
   	ts.tv_nsec = ht * 1000000;
   	cycletime = *(int*)ptr * 1000; /* cycletime in ns */
   	toff = 0;
   	dorun = 0;
   	ec_send_processdata();
   	while(1)
   	{
      /* calculate next cycle start */
      add_timespec(&ts, cycletime + toff);
      /* wait to cycle start */
      //clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, &tleft);
      if (dorun>0)
      {
         wkc = ec_receive_processdata(EC_TIMEOUTRET);
		outData++;
         dorun++;
         /* if we have some digital output, cycle */
         if( digout ) *digout = (uint8) ((dorun / 16) & 0xff);

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
		if (inOP && ((wkc < expectedWKC) || ec_group[currentgroup].docheckstate))
		{
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

int main(int argc, char *argv[])
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	// pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	

	dorun =0;
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
    osal_thread_create_rt(&thread1, stack64k * 2, &ecatthread, (void*) &cycleTime);
	/* start cyclic part */
	simpletest(d->name);

	printf("End program\n");
	return (0);
}

/* Callback function invoked by libpcap for every incoming packet (not used ??)*/
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
