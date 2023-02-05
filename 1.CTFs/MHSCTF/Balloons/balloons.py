from balloon_tracking_lookup import get_status

print "Welcome to your balloon order-tracking portal! Enter your tracking number here.\n"
tracking_number = input(">>> ")

try:
  print "Getting status for order #" + str(int(tracking_number)) + "..."
except:
  print "Invalid tracking number!"

print get_status(int(tracking_number))
