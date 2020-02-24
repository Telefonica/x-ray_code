# Ideas Locas CDO Telefónica
# SourceCode XrayCode Heatmap v1.0
# Static Code Engines supported: 
# - Bandit (Python) 
# - GoSec (GoLang) under construction

import subprocess
import re 
import argparse
import os
import json
import numpy as np
import seaborn as sns
import matplotlib
import matplotlib.pyplot as plt
import urllib
import urllib.request
from fpdf import FPDF
import shutil
from tqdm import tqdm
import requests

from matplotlib import cm as CM
from matplotlib import mlab as ML

# URL parsing
regex = re.compile(
    r'^(?:http|ftp)s?://' # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
    r'localhost|' #localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
    r'(?::\d+)?' # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)

class CodeHeat(object):

    def __init__(self, language):
        self.language=language
 
    def LoadSource(self,filename):
        totlines=0
        self.filename=filename
        i=0
        with open(self.filename) as f:
            for i, l in enumerate(f):
                pass
        totlines=i+1
        return(totlines)

    def LoadSourceURL(self, sourceurl):
        url = sourceurl #big file test
        # Streaming, so we can iterate over the response.
        r = requests.get(url, stream=True)
        # Total size in bytes.
        total_size = int(r.headers.get('content-length', 0))
        block_size = 1024 #1 KByte
        t=tqdm(total=total_size, unit='iB', unit_scale=True)
        with open('test.dat', 'wb') as f:
            for data in r.iter_content(block_size):
                t.update(len(data))
                f.write(data)
        t.close()
        if total_size == 0 and t.n != total_size:
            print("ERROR, something went wrong")


    def Extract_Vulnerabilities_Python(self, filetocheck, filejsoncheck, severitycheck):
        self.file=filetocheck
        self.filejson=filejsoncheck
        returncode=subprocess.call(['bandit', self.file, '-f','json','-o', self.filejson,'--quiet'])
        #returncode=subprocess.call(['bandit', self.file, '-f','json','-o', self.filejson])
        vul_list=[]

        a=0
        with open(self.filejson) as json_file:
            data = json.load(json_file)

            # Full heatmap
            if severitycheck=="ALL":
                for p in data['results']:
                    vul_list.append((p['line_number'],p['issue_severity'],p['test_id'],p['issue_text'],p['more_info']))
            # Rest of severity levels
            else:
                for p in data['results']:
                    if severitycheck==p['issue_severity']:
                        vul_list.append((p['line_number'],p['issue_severity'],p['test_id'],p['issue_text'],p['more_info']))

        return(vul_list)

    def DrawHeatmapDataPlasma(self, sourcelines, vulnerablelist, screen, severityp):
        N_numbers = 100000
        N_bins = 100
        # set random seed 0
        np.random.seed(0)
        # cov parameters risks levels
        # -4000 LOW
        # -200 MEDIUM
        # +1000 HIGH
        severitycode=0 
        # cov init data
        heatmapsize=200

        # Heatmap scatterd points size
        if sourcelines < 10:
            heatmapsize=10            
        elif sourcelines < 50:
            heatmapsize=20
        else:
            heatmapsize=200

        covx1=heatmapsize
        covx2=1
        covy1=1
        covy2=heatmapsize
        # Matrix initialization
        xx=[]
        yy=[]
        linenumberlist=[]

        # Draw vuln loop
        for record in vulnerablelist:
            lin_number=record[0]
            linenumberlist.append(lin_number)
            dataseverity=record[1]
            if dataseverity=='LOW':
                severitycode=-4000
            elif dataseverity=='MEDIUM':
                severitycode=-200
            elif dataseverity=='HIGH':
                severitycode=+1000
            else: 
                print("ERROR")
            #print(lin_number)

            x, y = np.random.multivariate_normal(
                mean=[0.0, lin_number],      # mean
                cov=[[covx1, covy1],
                    [covx2, covy2]],    # covariance matrix
                size=N_numbers
                ).T                   # transpose to get columns        
            xx=np.concatenate((x,xx))
            yy=np.concatenate((y,yy))

        # Add lines boundaries
        
            
        linenumberlist.insert(0,0)
        linenumberlist.insert(len(linenumberlist),sourcelines)

        #plt.rcParams["figure.facecolor"] = "b"
        plt.style.use('dark_background')
        plt.tick_params(
            axis='x',          # changes apply to the x-axis
            which='both',      # both major and minor ticks are affected
            bottom=False,      # ticks along the bottom edge are off
            top=False,         # ticks along the top edge are off
            labelbottom=False) # labels along the bottom edge are off

        # Construct 2D histogram from data using colormap palette
        
        if severityp=="ALL":
            plt.hist2d(xx, yy, bins=N_bins, density=False, cmap='inferno')
        elif severityp=="LOW":
            plt.hist2d(xx, yy, bins=N_bins, density=False, cmap='cubehelix') #check   
        elif severityp=="MEDIUM":
            plt.hist2d(xx, yy, bins=N_bins, density=False, cmap='gnuplot2')    
        elif severityp=="HIGH":
            plt.hist2d(xx, yy, bins=N_bins, density=False, cmap='afmhot')  #check        
        else:
            print("ERROR colormap")
        
        # Plot a colorbar adding label.
        cb = plt.colorbar()
        cb.set_label('Vulnerabilities Density')      
        cb.ax.set_yticklabels('')
        # Add title and labels to plot.
        plt.title('Vulnerabilities Heatmap '+severityp)
        #plt.grid(True)
        plt.subplots_adjust(left=0.25)      
        #plt.xlabel('x axis')
        plt.ylabel('Sorce Code Lines')
        plt.yticks(linenumberlist)
        plt.xlabel('File: %s' %filetocheck)
        #plt.xlabel('File: %s' %urltoanalize)
        plt.ylim(sourcelines,0)
        ax = plt.gca()
        ax.format_coord = lambda x,y: 'Line %0d, Pos %0d' % (y,x)

        # Save the plot to file
        plt.savefig(outputfolder+onlyfile+'.png')

        # Shows heatmap on screen 
        if screen=="on":
            # Show the plot
            plt.show()

        plt.clf()
        return  

    def CreatePDFReportHeader(self):
        # Report creation
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=34)
        
        for x in range(22):
            pdf.cell(ln=1, h=5.0, align='L', w=0, txt="", border=0)
        
        pdf.cell(200, 10, txt="XrayCode Heatmap Report", ln=1, align="C")
        pdf.set_font("Arial", size=20)
        pdf.cell(200, 10, txt="by Ideas Locas CDCO Telefonica", ln=1, align="C")
        return(pdf)

    def AddPDFReportData(self, completelistvul, pdfdoc, pathfile, outputimage):
        pdfdoc.add_page()
        pdfdoc.set_font("Arial", size=12)
        # add filename and path
        pdfdoc.cell(200, 10, txt="File: "+ pathfile, ln=1, align="L")
        pdfdoc.image(outputimage, x=10, y=20, w=180)
        pdfdoc.ln(85)  # move 85 down
        pdfdoc.set_font("Arial", size=10)
        for record in completelistvul:
            pdfdoc.cell(200, 10, txt="Line: "+str(record[0]), ln=1, align="L")
            pdfdoc.cell(200, 10, txt="Severity: "+str(record[1]), ln=1, align="L")
            pdfdoc.cell(200, 10, txt=str("Code: "+record[2]), ln=1, align="L")
            pdfdoc.cell(200, 10, txt=str("Description: "+record[3]), ln=1, align="L")
            pdfdoc.cell(200, 10, txt=str("More info: "+record[4]), ln=1, align="L")
            pdfdoc.cell(200, 10, txt=str(" "), ln=1, align="L")

        return(pdfdoc)


if __name__ == "__main__":
    fileoutputjson="check.json"
    #Set progamming language
    lang="python"
    so_heat=CodeHeat(lang)
    parser = argparse.ArgumentParser(description='Heatmap, X-Ray source code analysis by Ideas Locas CDCO ...')
    parser.add_argument("-i", required=True, type=str, help="Input folder to scan")    
    parser.add_argument("-o", required=True, type=str, help="Output folder to export results")
    parser.add_argument("-l", required=True, type=str, help="Severity (ALL, LOW, MEDIUM, HIGH)")
    parser.add_argument("-r", required=True, type=str, help="PDF file report name")
    parser.add_argument("-s", required=True, type=str, help="Show heatmap in screen (on/ofF)")
    args = parser.parse_args()
    i = args.i # Input folder
    o = args.o # Output folder
    l = args.l # Output folder
    r = args.r # PDF file name (report)
    s = args.s # Show heatmap on screen
    foldername=i
    outputfolder=o
    
    # Create folder if does not exist
    if not os.path.exists(outputfolder):
        os.makedirs(outputfolder)

    severitylevel=l
    finalpdf=so_heat.CreatePDFReportHeader()

    print("Scanning...")
    if lang=="python":
        # Is a folder, all files checked
        if not re.match(regex,i):
            for root, dirs, files in os.walk(foldername):
                for file in files:
                    if file.endswith(".py"):
                        print("Processing ... ",outputfolder+file)
                        filetocheck=os.path.join(root, file)
                        onlyfile=file
                        contentlines=so_heat.LoadSource(filetocheck)
                        vdetected=so_heat.Extract_Vulnerabilities_Python(filetocheck,fileoutputjson, severitylevel)                                        
                        if not vdetected:
                            shutil.copyfile("NoVulF.png",outputfolder+onlyfile+'.png')
                        else:
                            contentnumber=so_heat.DrawHeatmapDataPlasma(contentlines, vdetected, s,severitylevel)
                        pdfreport=so_heat.AddPDFReportData(vdetected, finalpdf, onlyfile, outputfolder+onlyfile+'.png')
                                  
        
        # Is a URL, single file
        else:
            objtoanalize=i
            filetocheck=objtoanalize
            onlyfile = objtoanalize[objtoanalize.rfind("/")+1:]
            so_heat.LoadSourceURL(objtoanalize)
            filetoanalyze="test.dat"
            contentlines=so_heat.LoadSource(filetoanalyze)
            vdetected=so_heat.Extract_Vulnerabilities_Python(filetoanalyze,fileoutputjson,severitylevel)
            contentnumber=so_heat.DrawHeatmapDataPlasma(contentlines, vdetected,s,severitylevel )
            pdfreport=so_heat.AddPDFReportData(vdetected, finalpdf, onlyfile, outputfolder+onlyfile+'.png')
    
    print("End")
    pdfreport.output(r)
