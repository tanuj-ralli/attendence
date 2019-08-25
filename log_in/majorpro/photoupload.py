import cv2
import os
cascPath = "/home/tanuj/project/major/application/log_in/majorpro/Webcam-Face-Detect-master/haarcascade_frontalface_default.xml"
faceCascade = cv2.CascadeClassifier(cascPath)
font = cv2.FONT_HERSHEY_SIMPLEX
video_capture = cv2.VideoCapture(0)

#frame = cv2.imread("/home/tanuj/project/major/application/log_in/majorpro/pic3.JPG")
ret, frame = video_capture.read()
frame = cv2.flip(frame, 1)
gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

faces = faceCascade.detectMultiScale(
    gray,
    scaleFactor=1.1,
    minNeighbors=5,
    minSize=(50, 50),
    flags=cv2.CASCADE_SCALE_IMAGE
    )
print("Found {0} faces!".format(len(faces)))
nn = 1
for (x, y, w, h) in faces:
    cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 255, 100), 1)
    crop_img = frame[y:y + h, x:x + w]
    # cv2.imshow("cropped", crop_img)
    cv2.imwrite("/home/tanuj/project/major/application/log_in/majorpro/croppedimages/"+str(nn)+".jpg",crop_img)
    nn = nn + 1

# DISPLAY THE RESULTING FRAME
cv2.imshow('Faces in image', frame)
cv2.waitKey(0)

count = 0
for i in os.listdir('/home/tanuj/project/major/application/log_in/majorpro/croppedimages/'):
    count = count + 1
    # image1=i
    image = cv2.imread(os.path.join('/home/tanuj/project/major/application/log_in/majorpro/croppedimages/', i))
    # gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    # reimage=padding_image(image)
    row, col, chan = image.shape
    # resize the original image as per requirement
    reimage = cv2.resize(image, (96, 96), interpolation=cv2.INTER_AREA)
    cv2.imwrite("/home/tanuj/project/major/application/log_in/majorpro/croppedimages2/" + str(i), reimage)
