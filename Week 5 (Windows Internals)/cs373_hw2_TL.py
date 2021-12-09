#**************************************************************************
#* File: cs373_hw2.py
#* Author: Tu Lam
#* Date: November 2nd, 2021
#* Description: The homework assignment asks us to print couple processes
#*              that is provided on the homework page and show them.
#**************************************************************************

# The import libraries needed for the program
import subprocess
import os


###############################################################
# (1. Enumerate all the running processes)
# The command can be found by running [ps -ax]

# Set var "process to hold the cmd 'ps' and all the necessary PIPE
# Make communciation to the stdout for printing
process = subprocess.Popen(['ps', '-ax'], stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
stdout, stderr = process.communicate()

# Print out the command
print("\n")
print("1. All Running Processes")
print(stdout)
print("\n")


###############################################################
# (2. List all running threads)
# The command is [ps -T -p]

# First get the OS to get the PID for process boundary
# Convert the PID to string for printing out the command
pid_num = os.getpid()
pid_str = str(pid_num)

# Get the value into a var for the cmd
run_thread = subprocess.check_output(['ps', '-T', '-p', pid_str])

# Print out the result
print("2. All Running Threads & Process Boundary")
print("Process Boundary PID: ", pid_num)
print(run_thread)
print("\n")


###############################################################
# (3. Enumerate all Loaded Modules)
# The command is [lsof -p]

# Assign the command with the right command and using the pid_str
module_cmd = subprocess.check_output(['lsof', '-p', pid_str])

# Print out the cmd
print("3. Enumerate all the Loaded Modules")
print(module_cmd)
print("\n")


###############################################################
# (4. Show Executable Pages)
# The cmd is [ps x | grep PID]

# First assign a str with the cmd to the pid_str
# Use the subprocess to print out the statement
cmd_str = "ps x | grep " + pid_str
exec_page = subprocess.check_output(cmd_str, shell = True)

# Print out the answer
print("4. Show the Executable Pages")
print(exec_page)
print("\n")


###############################################################
# (5. Capability to Read Memory)
# The cmd is [ps v PID]

# First assign the print item to var using subprocess
mem = subprocess.check_output(['ps', 'v', pid_str])

# Print out the content
print("5. Capability to Read Memory")
print(mem)
print("\n")