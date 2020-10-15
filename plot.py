#imports
import matplotlib.pyplot as pyplot
import numpy
import csv
import getopt
import sys
import re

#variables
_debug = 0
ecart = []
debit =[]
ec_DCtime = []
framesCount = 0
timeInSec = []
outpdo = []
infoStr = ""
nbOfbytes = []
inpdo = []
equalTime = 0
missedVal = 0
cycleTime = []
def plot_results():
    """plot data"""
    print('plotting')
    fig = pyplot.figure()
    ax1 = pyplot.subplot(211)
    ax1.set_ylabel("Trames entre 2 itérations de TxPDO")
    ax1.grid(True)
    ax1.scatter(numpy.linspace(0,len(cycleTime),len(cycleTime)),cycleTime,marker='x')
    ax3 = pyplot.subplot(212)
    ax3.set_ylabel("Debit")
    ax3.grid(True)
    ax3.plot(numpy.linspace(0,len(debit),len(debit)),debit)
    pyplot.show()
    


def arg_handler(argv):
    """manage arguments and return csvin"""

    try:
        opts, args = getopt.getopt(argv,"hi:d",["help","input="])
    except getopt.GetoptError:
        print("plot.py -i <inputfile>")
        sys.exit(2)

    for opt, args in opts:
        if opt in ("-h","--help"):
            print("Usage : plot.py -i <inputfile>")
            sys.exit()
        elif opt == "-d":
            global _debug
            _debug = 1
        elif opt in ("-i","--input"):
            csvin = open(args, newline='')
        else:
            print("Usage : plot.py -i <inputfile>")
    return csvin

def csv_parser(csvin):
        # parse csv with first row as dictionary
    allData = csv.DictReader(csvin)
    framesCount = 0
    prevvalue = 0
    equalTime = 0
    missedVal = 0
    # initialize and fetch useful data from csv
    prevtime = 0
    for row in allData:
        framesCount += 1

        if row['Data'] != '':
            pdoData = row['Data']
        
        if row['Working Cnt'] != '' and int(row['Working Cnt'].split(',')[0],10) == 12 and int(pdoData[:1],16) != 0:
            pdoData = row['Data']
            if pdoData != '':
                pdoDataBa = (bytearray.fromhex(pdoData[:8]))
                pdoDataBa.reverse()
                pdoData = pdoDataBa.hex()
                outpdo.append(int(pdoData,base=16))
                if int(pdoData,16) > (prevvalue+2) and prevvalue!=0:
                    missedVal +=1
                    print("lost",row['Time'])
            else:
                outpdo.append(0)
            if row['DC SysTime (0x910)'] != '':
                ec_DCtime.append(int(row['DC SysTime (0x910)'],base=16)/1e9)
            else:
                ec_DCtime.append(0)
            nbOfbytes.append(int(row['Length']))
            if float(row["Time"]) == prevtime:
                equalTime += 1
                #print("equal", float(row["Time"]))
            timeInSec.append(float(row["Time"]))
            prevtime = float(row["Time"])
            prevvalue = int(pdoData,base=16)
    return framesCount,missedVal,equalTime

def time_calc():
    # time is 0 at start of csv
    intialtime = ec_DCtime[0]
    for i,j in enumerate(timeInSec[:-1]):
        cycleTime.append(timeInSec[i+1]-j)
        #print(ec_DCtime[i+1]-j)

    # time btw 2 frames
    # for x,y in enumerate(timeInSec[:-1]):
    #     debit.append(nbOfbytes[x]/(timeInSec[x+1]-timeInSec[x]))
    x = 0
    step = 100
    while x<len(timeInSec) - step:
         debit.append(nbOfbytes[x]*step/(timeInSec[x+step]-timeInSec[x]))
         x += step

    # calculate nb of frames until PDO iteration
    n = 0
    for i,j in enumerate(outpdo[:-1]):
        if j == outpdo[i+1]:
            n = n+1
        else :
            ecart.append(n)
            n = 0

#main function
def main(argv):
    (fc,missedVal,equalTime) = csv_parser(arg_handler(argv))
    time_calc()
    print("Parsed",fc,"frames of data =",len(outpdo),"cycles\n")
    print("Found",equalTime,"frames with same Ws TimeStamp\n")
    print("There's",missedVal,"missed values (lost frames ?)\n")
    print("Average nb of frames per iter",round(sum(ecart)/len(ecart),2),"\n")
    print("Cycle time (s) : Average",round(sum(cycleTime)/len(cycleTime),9),"Max : ",max(cycleTime))
    print("min :",min(cycleTime))
    plot_results()

    input("Press enter to exit ...")


if __name__ == "__main__":
    main(sys.argv[1:])