#!/bin/sh

# Make sure the system time is synchronized
chronyd -q || (echo "Failed to sync time. Shutting down..." && poweroff -f)


dstack-util tboot
