# import face_recognition
# image = face_recognition.load_image_file
# face_locations = face_recognition.face_locations(image)
# print(face_locations)

import face_recognition
known_image = face_recognition.load_image_file("/home/tanuj/project/major/application/log_in/majorpro/88.jpg")
unknown_image = face_recognition.load_image_file("/home/tanuj/project/major/application/log_in/majorpro/8.jpg")

biden_encoding = face_recognition.face_encodings(known_image)[0]
unknown_encoding = face_recognition.face_encodings(unknown_image)[0]
print(biden_encoding,"===========",unknown_encoding)
print("=++++++++++++",type(biden_encoding),"===========",type(unknown_encoding))
print("0000000000000",biden_encoding,"11111111111",unknown_encoding.shape)
results = face_recognition.compare_faces([biden_encoding], unknown_encoding)
print(results)