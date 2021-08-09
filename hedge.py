from __future__ import print_function

import argparse
import sys
import bitarray
from time import time
import math
import os
import importlib

from sp800_22_all_tests import sp800_22_approximate_entropy_test


class Hedge():

    def __init__(self):
        self.testlist = [
            'frequency_within_block_test',
            'cumulative_sums_test',
            'runs_test',
            'approximate_entropy_test',
            ]

    def load_bits_from_file(self,filename):
        a = bitarray.bitarray()
        with open(filename, 'rb') as fh:
            a.fromfile(fh)
        tmp=a.to01()
        return map(int,tmp)

    def mono_test(self,bits):
        tmp="".join(map(str,bits))
        a = bitarray.bitarray(tmp)
        n = len(a)
        ones = a.count()
        zeroes=n-ones
        s = abs(ones-zeroes)

        p = math.erfc(float(s)/(math.sqrt(float(n)) * math.sqrt(2.0)))

        success = (p >= 0.01)

        return success

    def execute_tests(self, tcp_body):
        a = bitarray.bitarray()
        a.frombytes(tcp_body)
        bits = list(map(int,a.to01()))
        # mono = self.mono_test(bits)
        results = []

        # if mono==False:
        #     print ("[DEBUG]: Mono=False")
        #     return results
        if len(a) == 0:
            print("[DEBUG]: LENGTH=0")
            return results
        
        for testname in self.testlist:
            m = importlib.import_module("sp800_22_all_tests.sp800_22_" + testname)
            func = getattr(m, testname)
            (success,p,plist) = func(bits)
            summary_name = testname
            if success:
                # print("ENCRYPTED")
                summary_result = "ENCRYPTED"
            else:
                # print("COMPRESSED")
                summary_result = "COMPRESSED"

            if p != None:
                print("[DEBUG]: P="+str(p))
                summary_p = str(p)

            if plist != None:
                # for pval in plist:
                #     print("P="+str(pval))
                summary_p = str(min(plist))

            results.append((summary_name,summary_p, summary_result))
            # if summary_result == "COMPRESSED":
            #     break
        
        return results

    def final_verdict(self, results):
        values = [x[2] for x in results if x[2] == "COMPRESSED"]
        compressed_value = float(len(values))
        certainty = float(compressed_value/len(results))
        if certainty > 0.7:
            return "COMPRESSED"
        else:
            return "ENCRYPTED"
        

    def is_encrypted(self,results):
        is_encrypted = True
        for result in results:
            _,_, summary_result = result
            if summary_result=="COMPRESSED":
                is_encrypted = False
        return is_encrypted
        
    def print_summary(self,results):
        if not results:
            print("[DEBUG]: Mono=False")
            return
        print()
        print("SUMMARY")
        print("-------")
        print ("[DEBUG]: myresults=\n" + "\n".join(["Name:{} Result:{} ".format(el[0],el[2]) for el in results]))
        #print only one result
        if self.is_encrypted(results):
            print ("VERDICT:{}".format("ENCRYPTED"))
        else:
            print ("VERDICT:{}".format("COMPRESSED"))
            

def main(args):
    filename = args.filename
    hedge = Hedge()
    bits = hedge.load_bits_from_file(filename)
    results = hedge.execute_tests(bits)
    hedge.print_summary(results)
    # print("Tests of Distinguishability from Random")
    
    
if __name__ == '__main__':
    import argparse
    import sys
    parser = argparse.ArgumentParser(description='Test data for distinguishability form random, using NIST SP800-22Rev1a algorithms.')
    parser.add_argument('filename', type=str, nargs='?', help='Filename of binary file to test')
    parser.add_argument('--be', action='store_false',help='Treat data as big endian bits within bytes. Defaults to little endian')
    parser.add_argument('-t', '--testname', default=None,help='Select the test to run. Defaults to running all tests. Use --list_tests to see the list')
    parser.add_argument('--list_tests', action='store_true',help='Display the list of tests')

    alltest_list = [
        'monobit_test',
        'frequency_within_block_test',
        'runs_test',
        'longest_run_ones_in_a_block_test',
        'binary_matrix_rank_test',
        'dft_test',
        'non_overlapping_template_matching_test',
        'overlapping_template_matching_test',
        'maurers_universal_test',
        'linear_complexity_test',
        'serial_test',
        'approximate_entropy_test',
        'cumulative_sums_test',
        'random_excursion_test',
        'random_excursion_variant_test']

    args = parser.parse_args()
    if not os.path.exists(str(args.filename)):
        print("[ERROR]: Wrong path to file.")
        parser.print_help()
        exit()
    if args.list_tests:
        for i,testname in zip(range(len(alltest_list)),alltest_list):
            print(str(i+1).ljust(4)+": "+testname)
        exit()

    main(args)