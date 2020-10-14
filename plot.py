import matplotlib.pyplot as pyplot
import numpy 
import csv
import getopt
import sys
import re

#main function
def main(argv):
    # manage arguments
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

    source = "".join(args)
    
    # parse csv with first row as dictionary
    allData = csv.DictReader(csvin)

    # initialize and fill useful data from csv
    ec_DCtime = []
    timeInSec = []
    outpdo = []
    infoStr = ""
    nbOfbytes = []
    inpdo = []
    for row in allData:
        
        pdoData = row['Data']
        if pdoData != '':
            outpdo.append(pdoData[:7])
        else:
            outpdo.append(0)
        if row['DC SysTime (0x910)'] != '':
            ec_DCtime.append(int(row['DC SysTime (0x910)'],16))
        else:
            ec_DCtime.append(0)
        infoStr = row['Info']
        somme = 0
        for s in re.findall(r'\b\d+\b',infoStr):
            if int(s)>2:
                somme = somme + int(s)
        nbOfbytes.append(somme)
        timeInSec.append(float(row["Time"]))

    
    
    debit = []

    # time is 0 at start of csv
    intialtime = ec_DCtime[0]
    for i in enumerate(ec_DCtime):
        ec_DCtime[i[0]] -=  intialtime


    # time btw 2 frames
    # for x,y in enumerate(timeInSec[:-1]):
    #     debit.append(nbOfbytes[x]/(timeInSec[x+1]-timeInSec[x]))
    x = 0
    step = 300
    while x<len(timeInSec) - step:
         debit.append(nbOfbytes[x]*step/(timeInSec[x+step]-timeInSec[x]))
         x += step
     
    # calculate nb of frames until PDO iteration
    n = 0
    ecart = []
    for i,j in enumerate(outpdo[:-1]):
        if j == outpdo[i+1]:
            n = n+1
        else :
            ecart.append(n)
            n = 0

    # plot data
    print('plotting')
    # fig = pyplot.figure()
    fig = pyplot.figure()
    ax1 = pyplot.subplot(211)
    ax1.set_ylabel("Trames entre 2 itérations de TxPDO")
    ax1.grid(True)
    ax1.plot(numpy.linspace(0,len(ecart),len(ecart)),ecart)
    ax3 = pyplot.subplot(212)
    ax3.set_ylabel("Debit")
    ax3.grid(True)
    ax3.plot(numpy.linspace(0,len(debit),len(debit)),debit)
    pyplot.show()

    input("Press enter to exit ...")
    
    
if __name__ == "__main__":       
    main(sys.argv[1:])