import r2pipe
import matplotlib.pyplot as plt
import argparse
import os
import concurrent.futures

# TODO: Add an option to show an axis as hex values and bruteforce hex values
# TODO: Add option to set rip/eip equal to the first breakpoint instead of using a breakpoint

# Setup the argument parser
parser = argparse.ArgumentParser(description="Analyzes specified lines of code by executing the code using given input values, recording the output, and graphing the result.", usage='%(prog)s [options] filename start stop input output range')
parser.add_argument("filename", help="The name of the executable you would like to bruteforce.")
parser.add_argument("start", help="The first breakpoint will be set at this location. At the breakpoint, the input register or memory location will be changed to the next value in the range.")
parser.add_argument("stop", help="The second breakpoint will be set at this location. At the breakpoint, the output will be recorded.")
parser.add_argument("input", help="The register or memory location that contains the input value that should be bruteforced. Example: \"eax\". If using a memory location, please specify the location using m[location]. Example: \"m[rbp-0x8]\".")
parser.add_argument("output", help="The register or memory location that contains the output values that should be checked after the code is executed. Example: \"eax\". If using a memory location, please specify the location using m[location]. Example: \"m[rbp-0x8]\".")
parser.add_argument("range", help="The range of values that should be used for the input during the bruteforce process. Should be in the form \"[lower,upper]\" or \"[lower,upper,step]\". For example: [0,101,5] will use 0, 5, 10, ..., 95, 100 as the input values to be bruteforced. These must be in base 10 (hexadecimal or binary will not work).")
parser.add_argument("-t", "--threads", nargs='?', dest="threads", default="5", help="The number of threads that will be used during execution. Default value is 5.")
parser.add_argument("-in", "--standard-input", nargs='?', dest='input_file', default='', help="Uses the \'dor stdin=[INPUT_FILE]\' command in radare2 to make the executable read standard input from a given file instead of having the user type it in.")
parser.add_argument("-il", "--input-length", nargs='?', dest='input_length', default='1', help="The amount of bytes placed at the input memory location. Default value is 1, but this will be automatically adjusted if it is too small. Is only used if the input is a memory location and not a register.")
parser.add_argument("-ol", "--output-length", nargs='?', dest='output_length', default='1', help="The amount of bytes read at the output memory location. Must be equal to either 1, 2, 4, or 8. Default value is 1. Is only used if the output is a memory location and not a register.")
parser.add_argument("-e", "--execute", nargs='?', dest='commands', type=str, default='', help="Executes the given r2 commands in radare2 right after the debugger hits the first breakpoint, but before the input value is set. Example: -e \"dr ebx = 7\" will always set ebx equal to 7 at the first breakpoint. Multiple commands can be separated by a semicolon.")

# Parse all of the arguments
args = parser.parse_args()
filename = args.filename
start = args.start
stop = args.stop
bruteforce = args.input
bruteforceIsMem = False
if(bruteforce.startswith("m[") and bruteforce[-1]==']'):
    bruteforceIsMem = True
    bruteforce = bruteforce[2:-1]
output = args.output
outputIsMem = False
if(output.startswith("m[") and output[-1]==']'):
    outputIsMem = True
    output = output[2:-1]
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
input_file = args.input_file
input_length = args.input_length
output_length = args.output_length
commands = args.commands

# List of tuples that contain the input and its corresponding output. These points will eventually be plotted onto the graph.
points = []

def execute(value):
    """ Executes some code using the given input and returns the output. """
    # Load the binary in radare2
    r = r2pipe.open(filename, flags=['d', 'A'])

    # If the standard input option is set, then set use the dor command to set stdin to the given file
    if(input_file != ''):
        r.cmd('dor stdin=' + input_file)

    # Go to the memory location that we need to be at
    r.cmd('doo;db ' + start + ";db " + stop + ";dc")

    # Execute any r2 commands that the user wants to have executed
    r.cmd(commands)

    # Set the register/memory location that we are bruteforcing to the value that we want it
    if(bruteforceIsMem):
        hex_value = hex(value)[2:] # Convert the value to hex and delete the "0x" part of it
        r.cmd('w0 ' + input_length + " @" + bruteforce) # Clears out the memory at the location
        r.cmd('wB 0x' + hex_value + " @" + bruteforce) # Overwrites the memory location with the value that we are bruteforcing it with
    else:
        r.cmd('dr ' + bruteforce + ' = ' + str(value)) # If it's a register, then we just need to use the "dr" command.

    # Continue execution
    r.cmd('dc')

    # Read the value of the register/memory location that needs to be checked and record it
    result = 0
    if(outputIsMem):
        result = int(r.cmd('pv' + output_length + ' @' + output), 16)
    else:
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
