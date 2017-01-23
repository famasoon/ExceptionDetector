# coding: utf-8

import detector
import detector_defines
import sys

if len(sys.argv) < 2:
    print("Usage: python %s PID" % sys.argv[0])
    sys.exit()

detector = detector.detector()
pid = sys.argv[1]
detector.attach(int(pid))
detector.run()