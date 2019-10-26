import r2pipe
import matplotlib.pyplot as plt
import argparse
import os
import concurrent.futures

# TODO: Deal with input that comes before the starting location
# TODO: Add an option to set stdin to read from a file
# TODO: Add the option the change the value of certain registers right at the first breakpoint
# TODO: Allow users to bruteforce memory locations instead of just registers
# TODO: Add an option to show an axis as hex values

# Setup the argument parser
parser = argparse.ArgumentParser(description="Analyzes specified lines of code by executing the code using given input values, recording the output, and graphing the result.", usage='%(prog)s [options] filename start stop input output range')
parser.add_argument("filename", help="The name of the executable you would like to bruteforce.")
parser.add_argument("start", help="The first breakpoint will be set at this location. The input register or memory location will be changed to the next value in the range.")
parser.add_argument("stop", help="The second breakpoint will be set at this location. The output will be recorded at this location and the process will be stopped.")
parser.add_argument("input", help="The register or memory location that contains the input value that should be bruteforced.")
parser.add_argument("output", help="The register or memory location that contains the output values that should be checked after the code is executed.")
parser.add_argument("range", help="The range of values that should be used for the input during the bruteforce process. Should be in the form \"[lower,upper]\" or \"[lower,upper,step]\". For example: [0,101,5] will use 0, 5, 10, ..., 95, 100 as the input values to be bruteforced.")
parser.add_argument("-t", "--threads", nargs='?', dest="threads", default="5", help="The number of threads that will be used during execution. Default value is 5.")

# Parse all of the arguments
args = parser.parse_args()
filename = args.filename
start = args.start
stop = args.stop
bruteforce = args.input
output = args.output
valueRange = args.range.split(",")
lower_bound = int(valueRange[0].split("[")[1])
upper_bound = valueRange[1]
if("]" in upper_bound):
    upper_bound = int(upper_bound[:-1])
else:
    upper_bound = int(upper_bound)
step = 1
if(len(valueRange) == 3):
    step = int(valueRange[2][:-1])
threads = int(args.threads)

# List of tuples that contain the input and its corresponding output. These points will eventually be plotted onto the graph.
points = []

def execute(value):
    """ Executes some code using the given input and returns the output. """
    # Load the binary in radare2 and go to the memory location that we need to be at
    r = r2pipe.open(filename, flags=['d A Q'])
    r.cmd('doo;db ' + start + ";db " + stop + ";dc")

    # Set the register that we are bruteforcing
    r.cmd('dr ' + bruteforce + ' = ' + str(value))

    # Continue
    r.cmd('dc')

    # Read the value of the register that needs to be checked and record it
    result = int(r.cmd('dr ' + output).strip(), 16)

    # Add the point to the list of points
    points.append((value, result))

# Use a ThreadPoolExecutor to call execute() using range(lower_bound, upper_bound, step) in a given number of threads
with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
    executor.map(execute, range(lower_bound, upper_bound, step))

# Print out the points
print("Points:")
print(points)

# Convert the list of points into two tuples. The first tuple will contain the x values (inputs) and the second tuple will contain the y values (results). 
# This is done to convert the points into a format that matplotlib accepts
xy = zip(*points)

# Plot the graph
plt.scatter(*xy)
plt.title('Bruteforcing ' + bruteforce + ' @' + start)
plt.xlabel(bruteforce + '\'s starting values @' + start)
plt.ylabel(output + '\'s ending values @' + stop)
plt.show()
