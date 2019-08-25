import cv2
import numpy as np
import os
cascPath = "/home/tanuj/project/major/application/log_in/majorpro/Webcam-Face-Detect-master/haarcascade_frontalface_default.xml"
faceCascade = cv2.CascadeClassifier(cascPath)
font = cv2.FONT_HERSHEY_SIMPLEX
video_capture = cv2.VideoCapture(0)


nn=1
while True:
    ret, frame = video_capture.read()
    frame = cv2.flip(frame, 1)
    #frame = skimage.transform.rotate(frame,180)
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    faces = faceCascade.detectMultiScale(
        gray,
        scaleFactor=1.1,
        minNeighbors=5,
        minSize=(50, 50),
        flags=cv2.CASCADE_SCALE_IMAGE
        )
    print("Found {0} faces!".format(len(faces)))
    # DRAW A RECTANGLE AROUND THE FACES FOUND
    for (x, y, w, h) in faces:
        cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 255, 100), 1)
        crop_img = frame[y:y + h, x:x + w]
        # cv2.imshow("cropped", crop_img)
        cv2.imwrite("/home/tanuj/project/major/application/log_in/majorpro/takendataset/" + str(nn) + ".jpg", crop_img)
        nn = nn + 1

    # DISPLAY THE RESULTING FRAME
    cv2.imshow('Video', frame)

    if cv2.waitKey(1) & 0xFF == ord('q'):
        break
# When everything is done, release the capture
video_capture.release()
cv2.destroyAllWindows()


# initialize counter to count total no of images in the dataset
count = 0

for i in os.listdir('/home/tanuj/project/major/application/log_in/majorpro/takendataset/'):
    count = count + 1
    # image1=i
    image = cv2.imread(os.path.join('/home/tanuj/project/major/application/log_in/majorpro/takendataset/', i))
    # gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    # reimage=padding_image(image)
    row, col, chan = image.shape
    # resize the original image as per requirement

    reimage = cv2.resize(image, (96, 96), interpolation=cv2.INTER_AREA)
    for n in range(3):
        # initialze an array color required for padding
        coll = image[0, 0, n]  # coll = gray[row - 1, col - 1]
        color = [int(coll), int(coll), int(coll)]

        if row > col:
            teimage = reimage[:, :, n]
            row, col = teimage.shape
            left = right = ((96 - col) / 2)
            sqimage = cv2.copyMakeBorder(teimage, 0, 0, int(left), int(right), cv2.BORDER_CONSTANT, value=color)
            row, col = sqimage.shape
            if (row != col):
                sqimage = cv2.copyMakeBorder(sqimage, 0, 0, 0, 1, cv2.BORDER_CONSTANT, value=color)
            # overwrite the subsequent channel of original image
            reimage[:, :, n] = sqimage

        else:
            # reimage = image_resize(image[:,:,n], width=96)
            teimage = reimage[:, :, n]
            row, col = teimage.shape
            top = bottom = (96 - row) / 2
            sqimage = cv2.copyMakeBorder(teimage, int(top), int(bottom), 0, 0, cv2.BORDER_CONSTANT, value=color)
            row, col = sqimage.shape
            if (row != col):
                sqimage = cv2.copyMakeBorder(sqimage, 0, 1, 0, 0, cv2.BORDER_CONSTANT, value=color)
            # overwrite the subsequent channel of original image
            reimage[:, :, n] = sqimage

        # save the processed image in the new folder named embedding
    cv2.imwrite("/home/tanuj/project/major/application/log_in/majorpro/croppadding/" + str(i), reimage)
