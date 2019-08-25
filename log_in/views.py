from django.contrib.auth import authenticate, logout, login
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render, redirect, get_object_or_404
from .models import Myuser, LoginLogs, UserData, TeacherData, AttendanceDB
from .forms import MyuserForm, LoginLogsForm, UserDataForm, TeacherDataForm, UpdateAttendanceForm, AttendanceDBForm, OtpVeriForm, TeacherLoginForm, PasswordResetForm, PasswordResetWithTokenForm, PasswordChangeForm
from django.conf import settings
from django.views import generic
from django.http import HttpResponseRedirect, HttpResponse, HttpResponseServerError, Http404
from django.urls import reverse
from django.contrib.auth import get_user_model
import random, string
from django.core.mail import send_mail
from django.http import JsonResponse
from django.core import signing
from django.contrib import messages
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.decorators import login_required
from django.core.mail import EmailMessage
from django.contrib.sessions.models import Session
from django.contrib.auth import update_session_auth_hash
from django.utils.timezone import utc
from django.db.models import Q
import face_recognition

User = get_user_model()
import datetime
import time
def index(request):
    return render(request, 'log_in/index.html')

def LoginLogss(request):

    if  request.user.is_authenticated:
        return redirect('log_in:admin_profile')

    else:
        if request.method == 'POST':
            form = LoginLogsForm(request.POST)
            if form.is_valid():
                try:
                    user = authenticate(username=form.cleaned_data['email'], password=form.cleaned_data['password'])
                    if user:
                        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
                        if x_forwarded_for:
                            ip = x_forwarded_for.split(',')[0]
                        else:
                            ip = request.META.get('REMOTE_ADDR')
                        ide = User.objects.get(id=user.id)
                        ide.password_reset_token = None
                        ide.save()
                        obj = LoginLogs.objects.filter(email=form.cleaned_data['email']).latest('id')

                        # print('----------------id----------------',obj.id)
                        if obj.login_time and not obj.logout_time:
                                messages.error(request, 'Already logged in,log out from there to continue.')
                                return redirect('log_in:log_in')
                        else:
                            raise LoginLogs.DoesNotExist
                    else:
                        messages.error(request, 'Invalid Email OR Password')
                        return redirect('log_in:log_in')

                except LoginLogs.DoesNotExist:
                    o = LoginLogs(ip_address=ip,
                                  user_id=ide,
                                  logintry_time=datetime.datetime.now().isoformat(),
                                  agent=request.META['HTTP_USER_AGENT'],
                                  email=form.cleaned_data['email'],
                                  password=make_password(form.cleaned_data['password']),
                                  otp_verified=1,
                                  login_time = datetime.datetime.now().isoformat(),
                                  otp=''.join(
                                      random.choice(
                                          string.ascii_uppercase + string.ascii_lowercase + string.digits)
                                      for i
                                      in range(6))

                                  )
                    o.save()
                    # check = LoginLogs.objects.get(id=request.session['user.id'], email=user.email, otp=user.otp)
                    # if check:
                    obj = LoginLogs.objects.filter(email=form.cleaned_data['email']).latest('id')
                    request.session['idid'] = obj.id
                    login(request, user)
                    return redirect('log_in:admin_profile')


                except Exception as e:
                    print("Excpeth ", e)
                    return HttpResponseServerError(
                        'Some error occured during saving the data. Please try later or contact your administrator.')
        else:
            form = LoginLogsForm()
        return render(request, 'log_in/log_in.html', {'form': form})

@login_required
def admin_profile(request):
    user = User.objects.get(id=request.user.id)
    all_activities = LoginLogs.objects.filter(user_id=user.id)
    return render(request, 'log_in/admin_users_profile.html', {'object': all_activities, 'id': user.id, 'username': user.username, 'email': user.email })

@login_required
#To view the lists of ADMINS
def admin_users_list(request):
    return render(request, 'log_in/admin_users_list.html',{'admin':request.user.email})


@login_required
def admin_users_list_data(request):
    if request.method == 'GET':
        draw = int(request.GET.get('draw', 1))
        queryset_and_total_count = admin_user_get_queryset_and_count(request)
        total_count = queryset_and_total_count.get('total_count')
        queryset = queryset_and_total_count.get('queryset')
        response_data = [{
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'password': user.password,
            'is_active': user.is_active,
            'date_joined': user.date_joined,
            'updated_on': user.updated_on,
            'created_by': user.created_by_id,
            'updated_by': user.updated_by_id,
            # 'filename': name.filename,
        } for user in queryset]
        return JsonResponse(
            {'draw': draw, 'recordsTotal': total_count, 'recordsFiltered': total_count, 'data': response_data})
    else:
        return JsonResponse({})

def admin_user_get_queryset_and_count(request):
    start = int(request.GET.get('start', 0))
    length = int(request.GET.get('length', 10))
    total_count = User.objects.all()
    queryset = User.objects.all()
    total_count = total_count.count()


    order_column = request.GET.get('order[0][column]', None)
    if order_column == None:
        arguments='id'
    else:
        field = request.GET.get('columns['+order_column+'][data]', None)
        order = request.GET.get('order[0][dir]', None)
        if order == 'asc':
            arguments = field
        else:
            arguments = "-" + field


    search = request.GET.get('search[value]', None)
    if search:
        queryset = queryset.order_by(arguments).filter(Q(email__icontains=search)|Q(username__icontains=search))[start:length + start]
    else:
        queryset = queryset.order_by(arguments)[start:length + start]
    return {'queryset': queryset, 'total_count': total_count}


class MyuserCreateView(generic.CreateView):
    # Add new Admin
    queryset = Myuser.objects.all()
    template_name = 'log_in/add_admin.html'
    context_object_name = 'form'
    form_class = MyuserForm

    def form_valid(self, form):
        try:
            self.object = form.save(commit=True)
            return HttpResponseRedirect(reverse('log_in:admin_users_list'))
        except Exception as e:
            print("Excpeth ", e)
            return HttpResponseServerError(
                'Some error occured during saving the data. Please try later or contact your administrator.')

    def get_form_kwargs(self):
        kwargs = super(MyuserCreateView, self).get_form_kwargs()
        kwargs.update({'logged_admin': self.request.user.id})
        return kwargs

class MyuserUpdateView(generic.UpdateView):
    #Update Admin
    model = Myuser
    queryset = Myuser.objects.all()
    form_class = MyuserForm
    pk_url_kwarg = 'id'
    template_name = 'log_in/update_admin_user.html'
    context_object_name = 'form'

    def form_valid(self, form):
        try:
            self.object = form.save(commit=True)
            update_session_auth_hash(self.request, self.object)
            return HttpResponseRedirect(reverse('log_in:admin_users_list'))
        except Exception as e:
            print("Excpeth ", e)
            return HttpResponseServerError(
                'Some error occured during saving the data. Please try later or contact your administrator.')

    def get_form_kwargs(self):
        kwargs = super(MyuserUpdateView, self).get_form_kwargs()
        kwargs.update({'logged_admin': self.request.user.id})
        return kwargs

@login_required
def deleteadmin(request):
    #To Delete the Admin
    user_id = request.GET.get('user_id', None)
    instance = User.objects.get(pk=int(user_id))
    instance.delete()
    data = {'qwe': 'asd'}
    return JsonResponse(data)

@login_required
def activities_admin(request):
    #View Activities of Admin
    #print("in view_logs_list")
    user_id = request.GET.get('user_id', None)
    #print(user_id)
    obj = User.objects.get(id=user_id)
    #check = LoginLogs.objects.get(email=request.user.email, user_id=user_id)
    all_activities = LoginLogs.objects.filter(user_id=user_id)
    # print(check.email,check.id)
    # #print(check)
    return render(request, 'log_in/view_logs_list.html', {'object': all_activities, 'email' : obj.email})

@login_required
def password_change(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.POST)
        if form.is_valid():
            oldpassword = form.cleaned_data['old_password']
            newpassword = form.cleaned_data['new_password']
            renewpassword = form.cleaned_data['retype_newpassword']
            if not request.user.check_password(oldpassword):
                messages.error(request, 'Enter correct Old Password.')
                return redirect('log_in:password_change')
            else:
                if newpassword != renewpassword:
                    messages.error(request, 'Both New Password and Retype New Password should match. ')
                    return redirect('log_in:password_change')
                else:
                    idid = request.session['idid']
                    request.user.password = make_password(newpassword)
                    print(request.user.password)
                    request.user.save()
                    email=request.user.email
                    logout(request)
                    print(email)
                    try :
                        user = authenticate(username=email, password=newpassword)
                        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                        request.session['idid'] = idid
                        messages.error(request, 'Password Successfully changed ')
                        return redirect('log_in:password_change')
                    except Exception as e:
                        print("Excpeth ", e)
                        return HttpResponseServerError('Some error occured during saving the data. Please try later or contact your administrator.')
        else:
            print("Form ", form.errors)
    else:
        form = PasswordChangeForm()
    return render(request, 'log_in/change_password.html', {'form': form})

#forgot_password
def password_reset(request):
    form = PasswordResetForm()
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email_id = form.cleaned_data['email']
            if email_id:
                try:
                    user = get_user_model().objects.get(email=email_id)

                    obj = LoginLogs.objects.filter(email=user.email).latest('id')
                    print('-------------------id---------------', user.email, obj.logout_time, '====', (obj.login_time),
                          '====', (obj.id))
                    if not obj.logout_time and (obj.login_time):
                        obj.logout_time = datetime.datetime.now().isoformat()
                        obj.save()

                    raise LoginLogs.DoesNotExist
                except LoginLogs.DoesNotExist:
                    user = get_user_model().objects.get(email=email_id)
                    reset_token = get_token()
                    user.password_reset_token = reset_token
                    user.save()
                    encrypted_data = signing.dumps({'email': email_id, 'token': reset_token})
                    reset_url = settings.BASE_URL + 'log_in/password/reset/update/?token=' + encrypted_data
                    content = "<p>Please click the link below to reset your password<p>"
                    content += "<a href='" + reset_url + "'>" + reset_url + "</a>"
                    subject = 'Reset password'
                    to = email_id
                    from_mail = settings.EMAIL_HOST_USER
                    mail = EmailMessage(subject=subject, body=content, to=(to,), from_email=from_mail)
                    mail.content_subtype = 'html'
                    mail.send()
                    messages.success(request, 'We have successfully send a password reset link to your email ID.')
                    return HttpResponseRedirect(reverse('log_in:log_in'))

                except Exception as e:
                    messages.error(request, 'It seems that you have entered invalid email id.', extra_tags='danger')
                    return HttpResponseRedirect(reverse('log_in:log_in'))
            else:
                msg = 'Please enter the valid credentials.'
                return render(request, 'log_in/reset_password.html', {'form': form, 'error_msg': msg})
        else:
            return render(request, 'log_in/reset_password.html', {'form': form})
    else:
        return render(request, 'log_in/reset_password.html', {'form': form})


def get_token():
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in
            range(50))


def password_reset_using_token(request):
    if request.method == 'POST':
        token = request.POST.get("token")
        form = PasswordResetWithTokenForm(request.POST)
        if form.is_valid():
            try:
                print("in 2nd try")
                print('------',settings.BASE_URL +'log_in/password/reset/update/?token='+token)
                newpassword = form.cleaned_data['new_password']
                renewpassword = form.cleaned_data['retype_newpassword']
                decrypted_data = signing.loads(token)
                user_obj = get_user_model().objects.get(password_reset_token=decrypted_data['token'],email=decrypted_data['email'])
                if newpassword != renewpassword:
                    messages.error(request, 'Both New Password and Retype New Password should match. ')
                    return HttpResponseRedirect(settings.BASE_URL + 'log_in/password/reset/update/?token=' + token)
                else:
                    user_obj.password = make_password(newpassword)
                    user_obj.password_reset_token = None
                    user_obj.save()
                    messages.success(request, 'Your password has been successfully changed, Please login to check it.')
                    return HttpResponseRedirect(reverse('log_in:log_in'))

            except Exception as e:
                messages.error(request, 'Link expired,try again.')
                return HttpResponseRedirect(reverse('log_in:log_in'))

    else:
        token = request.GET.get('token', None)
        decrypted_data = signing.loads(token)
        decrypted_token = decrypted_data['token']
        decrypted_email = decrypted_data['email']
        #print('----------------decryptedtoken--------------',decrypted_token)
        obj = User.objects.get(email = decrypted_email)
        #print('----------------token--------------', obj.password_reset_token)
        if (decrypted_token != obj.password_reset_token) or token is  None:
            messages.error(request, 'Link expired,try again.')
            return HttpResponseRedirect(reverse('log_in:log_in'))
        else:
            form = PasswordResetWithTokenForm()
    return render(request, 'log_in/reset_password_with_token.html', {'form': form,'token':token})

@login_required
#To view the lists of TEACHERS
def teachers_list(request):
    return render(request, 'log_in/teachers_list.html',{'admin':request.user.email})


@login_required
def teachers_list_data(request):
    if request.method == 'GET':
        draw = int(request.GET.get('draw', 1))
        obj = TeacherData.objects.all()
        queryset_and_total_count = teachers_get_queryset_and_count(request)
        total_count = queryset_and_total_count.get('total_count')
        queryset = queryset_and_total_count.get('queryset')
        response_data = [{
            'id': user.id,
            'tid': user.tid,
            'tname': user.tname,
            'temail': user.temail,
            'tpassword': user.tpassword,
        } for user in queryset]
        return JsonResponse(
            {'draw': draw, 'recordsTotal': total_count, 'recordsFiltered': total_count, 'data': response_data})
    else:
        return JsonResponse({})

def teachers_get_queryset_and_count(request):
    start = int(request.GET.get('start', 0))
    length = int(request.GET.get('length', 10))
    total_count = TeacherData.objects.all()
    queryset = TeacherData.objects.all()
    total_count = total_count.count()


    order_column = request.GET.get('order[0][column]', None)
    if order_column == None:
        arguments='id'
    else:
        field = request.GET.get('columns['+order_column+'][data]', None)
        order = request.GET.get('order[0][dir]', None)
        if order == 'asc':
            arguments = field
        else:
            arguments = "-" + field


    search = request.GET.get('search[value]', None)
    if search:
        queryset = queryset.order_by(arguments).filter(Q(tname__icontains=search)|Q(temail__icontains=search))[start:length + start]
    else:
        queryset = queryset.order_by(arguments)[start:length + start]
    return {'queryset': queryset, 'total_count': total_count}

@login_required
def TeacherCreate(request):
    if request.method == 'POST':
        form = TeacherDataForm(request.POST, request.FILES)
        if form.is_valid():

            o = TeacherData(tname = form.cleaned_data['tname'],
                         tid=form.cleaned_data['tid'],
                         temail=form.cleaned_data['temail'],
                         tpassword=form.cleaned_data['tpassword'])
            o.save()
            return HttpResponseRedirect(reverse('log_in:teachers_list'))
        else:
            print("Form ", form.errors)
    else:
        form = TeacherDataForm()
    return render(request, 'log_in/add_teacher.html', {'form': form})


@login_required
def TeacherUpdate(request,id):
    if request.method == 'POST':
        form = TeacherDataForm(request.POST, request.FILES)
        up = get_object_or_404(TeacherData, pk=id)
        if form.is_valid():
            up.tid = form.cleaned_data['tid']
            up.tname = form.cleaned_data['tname']
            up.tpassword = form.cleaned_data['tpassword']
            up.temail = form.cleaned_data['temail']
            up.save()
            return redirect('log_in:teachers_list')

    else:
        up = get_object_or_404(TeacherData, pk=id)
        form = TeacherDataForm(request.POST or None,instance=up)
    print("=============id===========",id)
    return render(request, 'log_in/update_teacher.html', {'form': form, 'id' : id})

@login_required
def deleteteacher(request):
    #To Delete the user
    user_id = request.GET.get('teach_id', None)
    instance = TeacherData.objects.get(pk=int(user_id))
    instance.delete()
    data = {'qwe': 'asd'}
    return JsonResponse(data)


#Now functions for Students
@login_required
#To view the lists of STUDENTS
def users_list(request):
    return render(request, 'log_in/users_list.html',{'admin':request.user.email})


@login_required
def users_list_data(request):
    if request.method == 'GET':
        draw = int(request.GET.get('draw', 1))
        obj = UserData.objects.all()
        queryset_and_total_count = user_get_queryset_and_count(request)
        total_count = queryset_and_total_count.get('total_count')
        queryset = queryset_and_total_count.get('queryset')
        response_data = [{
            'id': user.id,
            'yod': user.yod,
            'branch': user.branch,
            'email': user.email,
            'rollno': user.rollno,
            'username': user.username,
            'foldername': user.foldername,
        } for user in queryset]
        return JsonResponse(
            {'draw': draw, 'recordsTotal': total_count, 'recordsFiltered': total_count, 'data': response_data})
    else:
        return JsonResponse({})

def user_get_queryset_and_count(request):
    start = int(request.GET.get('start', 0))
    length = int(request.GET.get('length', 10))
    total_count = UserData.objects.all()
    queryset = UserData.objects.all()
    total_count = total_count.count()


    order_column = request.GET.get('order[0][column]', None)
    if order_column == None:
        arguments='id'
    else:
        field = request.GET.get('columns['+order_column+'][data]', None)
        order = request.GET.get('order[0][dir]', None)
        if order == 'asc':
            arguments = field
        else:
            arguments = "-" + field


    search = request.GET.get('search[value]', None)
    if search:
        queryset = queryset.order_by(arguments).filter(Q(rollno__icontains=search)|Q(username__icontains=search))[start:length + start]
    else:
        queryset = queryset.order_by(arguments)[start:length + start]
    return {'queryset': queryset, 'total_count': total_count}

@login_required
def UserCreate(request):
    if request.method == 'POST':
        form = UserDataForm(request.POST, request.FILES)
        if form.is_valid():

            o = UserData(rollno = form.cleaned_data['rollno'],
                         yod=form.cleaned_data['yod'],
                         email=form.cleaned_data['email'],
                         branch=form.cleaned_data['branch'],
                         username=form.cleaned_data['username'],
                         foldername="Folder")
            o.save()
            request.session['as_rollno'] = form.cleaned_data['rollno']
            request.session['as_branch'] = form.cleaned_data['branch']
            request.session['as_yod'] = form.cleaned_data['yod']
            request.session['as_username'] = form.cleaned_data['username']

            request.session['rollno'] = form.cleaned_data['rollno']
            return HttpResponseRedirect(reverse('log_in:model_train'))
        else:
            print("Form ", form.errors)
    else:
        form = UserDataForm()
    return render(request, 'log_in/add_user.html', {'form': form})

@login_required
def ModelTrain(request):
    return render(request, 'log_in/dataset_and_training_of_model.html')

import cv2
import time
import os
import shutil

@login_required
def CollectDataset(request):
    cascPath = "/home/tanuj/project/major/application/log_in/majorpro/Webcam-Face-Detect-master/haarcascade_frontalface_default.xml"
    faceCascade = cv2.CascadeClassifier(cascPath)
    font = cv2.FONT_HERSHEY_SIMPLEX
    video_capture = cv2.VideoCapture(0)


    # while True:
    ret, frame = video_capture.read()
    frame = cv2.flip(frame, 1)
    # frame = skimage.transform.rotate(frame,180)
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
        reimage = cv2.resize(crop_img, (96, 96), interpolation=cv2.INTER_AREA)
        cv2.imwrite("/home/tanuj/project/major/application/log_in/majorpro/tempdataset/takenimage.jpg",reimage)

    # DISPLAY THE RESULTING FRAME
    cv2.imshow('Image', frame)
    #
    cv2.waitKey(0)
    # # When everything is done, release the capture
    video_capture.release()
    cv2.destroyAllWindows()

    # initialize counter to count total no of images in the dataset

    reimage = cv2.imread('/home/tanuj/project/major/application/log_in/majorpro/tempdataset/takenimage.jpg')

    rollno = request.session['as_rollno']
    branch = request.session['as_branch']
    yod = request.session['as_yod']
    username = request.session['as_username']
    if os.path.exists("/home/tanuj/project/major/application/log_in/majorpro/datasets/"+str(yod)):
        if os.path.exists("/home/tanuj/project/major/application/log_in/majorpro/datasets/"+str(yod)+"/"+str(branch)):
            if os.path.exists("/home/tanuj/project/major/application/log_in/majorpro/datasets/"+str(yod)+"/"+str(branch) + "/" + str(rollno) + "_" + str(username)):
                cv2.imwrite("/home/tanuj/project/major/application/log_in/majorpro/datasets/" + str(yod) + "/" + str(branch) + "/" + str(rollno) + "_" + str(username) + "/image.jpg", reimage)
            else:
                os.mkdir("/home/tanuj/project/major/application/log_in/majorpro/datasets/" + str(yod) + "/" + str(branch) + "/" + str(rollno) + "_" + str(username))
                cv2.imwrite("/home/tanuj/project/major/application/log_in/majorpro/datasets/" + str(yod) + "/" + str(branch) + "/" + str(rollno) + "_" + str(username) + "/image.jpg", reimage)
        else:
            os.mkdir("/home/tanuj/project/major/application/log_in/majorpro/datasets/"+str(yod)+"/"+str(branch))
            if os.path.exists("/home/tanuj/project/major/application/log_in/majorpro/datasets/"+str(yod)+"/"+str(branch) + "/" + str(rollno) + "_" + str(username)):
                cv2.imwrite("/home/tanuj/project/major/application/log_in/majorpro/datasets/" + str(yod) + "/" + str(branch) + "/" + str(rollno) + "_" + str(username) + "/image.jpg", reimage)
            else:
                os.mkdir("/home/tanuj/project/major/application/log_in/majorpro/datasets/" + str(yod) + "/" + str(branch) + "/" + str(rollno) + "_" + str(username))
                cv2.imwrite("/home/tanuj/project/major/application/log_in/majorpro/datasets/" + str(yod) + "/" + str(branch) + "/" + str(rollno) + "_" + str(username) + "/image.jpg", reimage)
    else:
        os.mkdir("/home/tanuj/project/major/application/log_in/majorpro/datasets/"+str(yod))
        if os.path.exists("/home/tanuj/project/major/application/log_in/majorpro/datasets/" +str(yod)+"/"+str(branch)):
            if os.path.exists("/home/tanuj/project/major/application/log_in/majorpro/datasets/"+str(yod)+"/"+str(branch) + "/" + str(rollno) + "_" + str(username)):
                cv2.imwrite("/home/tanuj/project/major/application/log_in/majorpro/datasets/" + str(yod) + "/" + str(branch) + "/" + str(rollno) + "_" + str(username) + "/image.jpg", reimage)
            else:
                os.mkdir("/home/tanuj/project/major/application/log_in/majorpro/datasets/" + str(yod) + "/" + str(branch) + "/" + str(rollno) + "_" + str(username))
                cv2.imwrite("/home/tanuj/project/major/application/log_in/majorpro/datasets/" + str(yod) + "/" + str(branch) + "/" + str(rollno) + "_" + str(username) + "/image.jpg", reimage)
        else:
            os.mkdir("/home/tanuj/project/major/application/log_in/majorpro/datasets/" +str(yod)+"/"+str(branch))
            if os.path.exists("/home/tanuj/project/major/application/log_in/majorpro/datasets/"+str(yod)+"/"+str(branch) + "/" + str(rollno) + "_" + str(username)):
                cv2.imwrite("/home/tanuj/project/major/application/log_in/majorpro/datasets/" + str(yod) + "/" + str(branch) + "/" + str(rollno) + "_" + str(username) + "/image.jpg", reimage)
            else:
                os.mkdir("/home/tanuj/project/major/application/log_in/majorpro/datasets/" + str(yod) + "/" + str(branch) + "/" + str(rollno) + "_" + str(username))
                cv2.imwrite("/home/tanuj/project/major/application/log_in/majorpro/datasets/" + str(yod) + "/" + str(branch) + "/" + str(rollno) + "_" + str(username) + "/image.jpg", reimage)

        # save the processed image in the new folder named embedding
        # cv2.imwrite("/home/tanuj/project/major/application/log_in/majorpro/croppadding/" + str(i), reimage)
    shutil.rmtree("/home/tanuj/project/major/application/log_in/majorpro/tempdataset/")
    os.mkdir("/home/tanuj/project/major/application/log_in/majorpro/tempdataset/")
    return redirect('log_in:model_train')


@login_required
def UserUpdate(request,id):
    if request.method == 'POST':
        form = UserDataForm(request.POST, request.FILES)
        up = get_object_or_404(UserData, pk=id)
        if form.is_valid():
            up.yod = form.cleaned_data['yod']
            up.branch = form.cleaned_data['branch']
            up.email = form.cleaned_data['email']
            up.rollno = form.cleaned_data['rollno']
            up.username = form.cleaned_data['username']
            up.save()
            return redirect('log_in:users_list')

    else:
        up = get_object_or_404(UserData, pk=id)
        form = UserDataForm(request.POST or None,instance=up)
    print("=============id===========",id)
    return render(request, 'log_in/update_user.html', {'form': form, 'id' : id})

@login_required
def deleteuser(request):
    #To Delete the user
    user_id = request.GET.get('user_id', None)
    instance = UserData.objects.get(pk=int(user_id))
    instance.delete()
    data = {'qwe': 'asd'}
    return JsonResponse(data)

def TeacherLogin(request):
    if request.method == 'POST':
        form = TeacherLoginForm(request.POST)
        if form.is_valid():
            try:
                obj = TeacherData.objects.get(tid=form.cleaned_data['tid'])
                if(obj.tpassword != form.cleaned_data['tpassword']):
                    messages.error(request, 'Invalid Password')
                    return redirect('log_in:teacherlogin')
                request.session['tid'] = form.cleaned_data['tid']
                return redirect('log_in:teacherdash')
            except TeacherData.DoesNotExist:
                messages.error(request, 'Invalid Teacher ID')
                return redirect('log_in:teacherlogin')
            except Exception as e:
                print("Excpeth====================", e)
                messages.error(request, 'Some error occured during saving the data. Please try later or contact your administrator.')
                return redirect('log_in:teacherlogin')
        else:
            print("Form ", form.errors)

    else:
        form = TeacherLoginForm()
    return render(request, 'log_in/teacher_log_in.html', {'form': form})

def TeacherDash(request):

    if request.method == 'POST':
        form = AttendanceDBForm(request.POST)
        if form.is_valid():

            date = form.cleaned_data['date'],
            branch = form.cleaned_data['branch'],
            yod = form.cleaned_data['yod'],
            subject = form.cleaned_data['subject']

            o = AttendanceDB(date=form.cleaned_data['date'],
                            branch=form.cleaned_data['branch'],
                            yod=form.cleaned_data['yod'],
                            subject=form.cleaned_data['subject'])
            o.save()

            dstDir = "/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(
                                yod[0]) + "/" + str(branch[0]) + "/" + str(subject) + "/" + str(date[0] + "/image.jpg")

            filePath = "/home/tanuj/project/major/application/log_in/majorpro/tempattendancefullimage/image.jpg"

            if os.path.exists("/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(yod[0])):
                if os.path.exists(
                        "/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(yod[0]) + "/" + str(
                                branch[0])):
                    if os.path.exists(
                            "/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(yod[0]) + "/" + str(
                                    branch[0]) + "/" + str(subject)):
                        if os.path.exists("/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(
                                yod[0]) + "/" + str(branch[0]) + "/" + str(subject) + "/" + str(date[0])):
                            shutil.copyfile(filePath, dstDir)
                        else:
                            os.mkdir("/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(
                                yod[0]) + "/" + str(branch[0]) + "/" + str(subject) + "/" + str(date[0]))
                            shutil.copyfile(filePath, dstDir)
                    else:
                        os.mkdir(
                            "/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(yod[0]) + "/" + str(
                                branch[0]) + "/" + str(subject))
                        if os.path.exists("/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(
                                yod[0]) + "/" + str(branch[0]) + "/" + str(subject) + "/" + str(date[0])):
                            shutil.copyfile(filePath, dstDir)
                        else:
                            os.mkdir("/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(
                                yod[0]) + "/" + str(branch[0]) + "/" + str(subject) + "/" + str(date[0]))
                            shutil.copyfile(filePath, dstDir)

                else:
                    os.mkdir("/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(yod[0]) + "/" + str(
                        branch[0]))
                    if os.path.exists(
                            "/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(yod[0]) + "/" + str(
                                    branch[0]) + "/" + str(subject)):
                        if os.path.exists("/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(
                                yod[0]) + "/" + str(branch[0]) + "/" + str(subject) + "/" + str(date[0])):
                            shutil.copyfile(filePath, dstDir)
                        else:
                            os.mkdir("/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(
                                yod[0]) + "/" + str(branch[0]) + "/" + str(subject) + "/" + str(date[0]))
                            shutil.copyfile(filePath, dstDir)
                    else:
                        os.mkdir(
                            "/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(yod[0]) + "/" + str(
                                branch[0]) + "/" + str(subject))
                        if os.path.exists("/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(
                                yod[0]) + "/" + str(branch[0]) + "/" + str(subject) + "/" + str(date[0])):
                            shutil.copyfile(filePath, dstDir)
                        else:
                            os.mkdir("/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(
                                yod[0]) + "/" + str(branch[0]) + "/" + str(subject) + "/" + str(date[0]))
                            shutil.copyfile(filePath, dstDir)
            else:
                os.mkdir("/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(yod[0]))
                if os.path.exists(
                        "/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(yod[0]) + "/" + str(
                                branch[0])):
                    if os.path.exists(
                            "/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(yod[0]) + "/" + str(
                                    branch[0]) + "/" + str(subject)):
                        if os.path.exists("/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(
                                yod[0]) + "/" + str(branch[0]) + "/" + str(subject) + "/" + str(date[0])):
                            shutil.copyfile(filePath, dstDir)
                        else:
                            os.mkdir("/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(
                                yod[0]) + "/" + str(branch[0]) + "/" + str(subject) + "/" + str(date[0]))
                            shutil.copyfile(filePath, dstDir)
                    else:
                        os.mkdir(
                            "/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(yod[0]) + "/" + str(
                                branch[0]) + "/" + str(subject))
                        if os.path.exists("/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(
                                yod[0]) + "/" + str(branch[0]) + "/" + str(subject) + "/" + str(date[0])):
                            shutil.copyfile(filePath, dstDir)
                        else:
                            os.mkdir("/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(
                                yod[0]) + "/" + str(branch[0]) + "/" + str(subject) + "/" + str(date[0]))
                            shutil.copyfile(filePath, dstDir)
                else:
                    os.mkdir("/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(yod[0]) + "/" + str(
                        branch[0]))
                    if os.path.exists(
                            "/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(yod[0]) + "/" + str(
                                    branch[0]) + "/" + str(subject)):
                        if os.path.exists("/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(
                                yod[0]) + "/" + str(branch[0]) + "/" + str(subject) + "/" + str(date[0])):
                            shutil.copyfile(filePath, dstDir)
                        else:
                            os.mkdir("/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(
                                yod[0]) + "/" + str(branch[0]) + "/" + str(subject) + "/" + str(date[0]))
                            shutil.copyfile(filePath, dstDir)
                    else:
                        os.mkdir(
                            "/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(yod[0]) + "/" + str(
                                branch[0]) + "/" + str(subject))
                        if os.path.exists("/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(
                                yod[0]) + "/" + str(branch[0]) + "/" + str(subject) + "/" + str(date[0])):
                            shutil.copyfile(filePath, dstDir)
                        else:
                            os.mkdir("/home/tanuj/project/major/application/log_in/majorpro/datasetattendance/" + str(
                                yod[0]) + "/" + str(branch[0]) + "/" + str(subject) + "/" + str(date[0]))
                            shutil.copyfile(filePath, dstDir)

            FRmodel = faceRecoModel(input_shape=(3, 96, 96))

            classobj = AttendanceDB.objects.filter(yod=form.cleaned_data['yod']) \
                .filter(branch=form.cleaned_data['branch']) \
                .filter(date=form.cleaned_data['date']) \
                .filter(subject=form.cleaned_data['subject'])
            roll = 'nodata'
            for i in os.listdir('/home/tanuj/project/major/application/log_in/majorpro/tempattendance2/'):
            #     arr2 = img_to_encoding(os.path.join("/home/tanuj/project/major/application/log_in/majorpro/tempattendance2/", i),
            #                     FRmodel)
                img = face_recognition.load_image_file(os.path.join("/home/tanuj/project/major/application/log_in/majorpro/tempattendance2/", i))
                arr2 = face_recognition.face_encodings(img)[0]
                obje = UserData.objects.filter(yod=form.cleaned_data['yod'])\
                .filter(branch=form.cleaned_data['branch'])
                dist=0
                for z_mean in obje:
                    z_mean.foldername = z_mean.foldername.replace("[", "")
                    z_mean.foldername = z_mean.foldername.replace("]", "")
                    z_mean.foldername = z_mean.foldername.replace("    ", " ")
                    z_mean.foldername = z_mean.foldername.replace("   ", " ")
                    z_mean.foldername = z_mean.foldername.replace("  ", " ")
                    temp = np.fromstring(z_mean.foldername, sep=' ')
                    # print("55555555555555555",temp,"888888888888",type(temp))
                    # temp = np.reshape(temp, (1, 128))
                    # print("----------",arr2,"-=================",[temp])
                    #print("+++++++++",arr2.shape,"00000000000000000",type([temp]))
                    results = face_recognition.compare_faces([temp], arr2)
                    # print("-----------------",results,"-------------------",type(results))
                    if results == [True]:
                        # dist = np.linalg.norm(temp - arr2)
                        roll = z_mean.rollno

                if roll == 's1':
                    classobj.update(s1=1)
                elif roll == 's2':
                    classobj.update(s2=1)
                elif roll == 's3':
                    classobj.update(s3=1)
                elif roll == 's4':
                    classobj.update(s4=1)
                elif roll == 's5':
                    classobj.update(s5=1)
                elif roll == 's6':
                    classobj.update(s6=1)
                elif roll == 's7':
                    classobj.update(s7=1)
                elif roll == 's8':
                    classobj.update(s8=1)
                elif roll == 's9':
                    classobj.update(s9=1)
                elif roll == 's10':
                    classobj.update(s10=1)

                if roll == 'nodata':
                    messages.error(request,'No Records in database. Kindly update database to mark student as present.')
                else:
                    messages.error(request, 'Attendance of ' + o.subject + ', branch: ' + o.branch + ', dated: ' + str(
                        o.date) + ' has been uploaded.')

            shutil.rmtree("/home/tanuj/project/major/application/log_in/majorpro/tempattendance2/")
            os.mkdir("/home/tanuj/project/major/application/log_in/majorpro/tempattendance2/")
            shutil.rmtree("/home/tanuj/project/major/application/log_in/majorpro/tempattendance/")
            os.mkdir("/home/tanuj/project/major/application/log_in/majorpro/tempattendance/")
            shutil.rmtree("/home/tanuj/project/major/application/log_in/majorpro/tempattendancefullimage/")
            os.mkdir("/home/tanuj/project/major/application/log_in/majorpro/tempattendancefullimage/")

            return HttpResponseRedirect(reverse('log_in:teacherdash'))
        else:
            print("Form ", form.errors)

    tid = request.session['tid']
    obj = TeacherData.objects.get(tid=tid)
    form = AttendanceDBForm
    return render(request, 'log_in/welcome_teacher.html', {'name': obj.tname, 'form':form})

def PhotoUpload(request):
    cascPath = "/home/tanuj/project/major/application/log_in/majorpro/Webcam-Face-Detect-master/haarcascade_frontalface_default.xml"
    faceCascade = cv2.CascadeClassifier(cascPath)
    font = cv2.FONT_HERSHEY_SIMPLEX
    video_capture = cv2.VideoCapture(0)

    # frame = cv2.imread("/home/tanuj/project/major/application/log_in/majorpro/image.jpg")
    ret, frame = video_capture.read()
    frame = cv2.flip(frame, 1)
    cv2.imwrite("/home/tanuj/project/major/application/log_in/majorpro/tempattendancefullimage/image.jpg", frame)
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
        cv2.imwrite("/home/tanuj/project/major/application/log_in/majorpro/tempattendance/" + str(nn) + ".jpg", crop_img)
        nn = nn + 1

    # DISPLAY THE RESULTING FRAME
    cv2.imshow('Faces in image', frame)
    cv2.waitKey(0)
    video_capture.release()
    cv2.destroyAllWindows()

    count = 0
    for i in os.listdir('/home/tanuj/project/major/application/log_in/majorpro/tempattendance/'):
        count = count + 1
        # image1=i
        image = cv2.imread(os.path.join('/home/tanuj/project/major/application/log_in/majorpro/tempattendance/', i))
        # gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        # reimage=padding_image(image)
        row, col, chan = image.shape
        # resize the original image as per requirement
        reimage = cv2.resize(image, (96, 96), interpolation=cv2.INTER_AREA)
        cv2.imwrite("/home/tanuj/project/major/application/log_in/majorpro/tempattendance2/" + str(i), reimage)

    return redirect('log_in:teacherdash')

def Attendance(request):
    tid = request.session['tid']
    obj = TeacherData.objects.get(tid=tid)
    if request.method == 'POST':
        form = AttendanceDBForm(request.POST)
        if form.is_valid():
            request.session['edate']=date=form.cleaned_data['date'],
            request.session['ebranch']=branch=form.cleaned_data['branch'],
            request.session['eyear']=yod=form.cleaned_data['yod'],
            request.session['esubject']=subject=form.cleaned_data['subject']
            return render(request, 'log_in/db_display.html', {'name': obj.tname})

        else:
            print("Form ", form.errors)
    form = AttendanceDBForm
    return render(request, 'log_in/db_display_form.html', {'name': obj.tname, 'form':form})

def attendance_list(request):
    tid = request.session['tid']
    obj = TeacherData.objects.get(tid=tid)
    return render(request, 'log_in/db_display.html', {'name': obj.tname})

def attendance_list_data(request):
    if request.method == 'GET':
        draw = int(request.GET.get('draw', 1))
        obj = AttendanceDB.objects.all()
        queryset_and_total_count = attendance_get_queryset_and_count(request)
        total_count = queryset_and_total_count.get('total_count')
        queryset = queryset_and_total_count.get('queryset')
        response_data = [{
            'id': user.id,
            'date': user.date,
            'subject': user.subject,
            'yod': user.yod,
            'branch': user.branch,
            'student1': user.s1,
            'student2': user.s2,
            'student3': user.s3,
            'student4': user.s4,
            'student5': user.s5,
            'student6': user.s6,
            'student7': user.s7,
            'student8': user.s8,
            'student9': user.s9,
            'student10': user.s10,
        } for user in queryset]
        return JsonResponse(
            {'draw': draw, 'recordsTotal': total_count, 'recordsFiltered': total_count, 'data': response_data})
    else:
        return JsonResponse({})

def attendance_get_queryset_and_count(request):
    start = int(request.GET.get('start', 0))
    length = int(request.GET.get('length', 10))
    edate = request.session['edate']
    ebranch = request.session['ebranch']
    eyear = request.session['eyear']
    esubject = request.session['esubject']

    print("date=======",edate[0],"b2++++++++++",esubject,eyear[0],ebranch[0])

    if edate[0] == None:
        print("Date == None")
        total_count = AttendanceDB.objects.filter(subject=esubject).filter(yod=eyear[0]).filter(branch=ebranch[0])
        queryset = AttendanceDB.objects.filter(subject=esubject).filter(yod=eyear[0]).filter(branch=ebranch[0])
    else:
        print("Date == Not None")
        total_count = AttendanceDB.objects.filter(date=edate[0]) \
            .filter(subject=esubject).filter(yod=eyear[0]).filter(branch=ebranch[0])
        queryset = AttendanceDB.objects.filter(date=edate[0]) \
            .filter(subject=esubject).filter(yod=eyear[0]).filter(branch=ebranch[0])

    total_count = total_count.count()
    order_column = request.GET.get('order[0][column]', None)
    if order_column == None:
        arguments='id'
    else:
        field = request.GET.get('columns['+order_column+'][data]', None)
        order = request.GET.get('order[0][dir]', None)
        if order == 'asc':
            arguments = field
        else:
            arguments = "-" + field


    search = request.GET.get('search[value]', None)
    if search:
        queryset = queryset.order_by(arguments).filter(Q(subject__icontains=search)|Q(branch__icontains=search))[start:length + start]
    else:
        queryset = queryset.order_by(arguments)[start:length + start]
    return {'queryset': queryset, 'total_count': total_count}

def UpdateAttendance(request,id):
    if request.method == 'POST':
        form = UpdateAttendanceForm(request.POST, request.FILES)
        up = get_object_or_404(AttendanceDB, pk=id)
        if form.is_valid():
            up.date = form.cleaned_data['date']
            up.subject = form.cleaned_data['subject']
            up.yod = form.cleaned_data['yod']
            up.branch = form.cleaned_data['branch']
            up.s1 = form.cleaned_data['s1']
            up.s2 = form.cleaned_data['s2']
            up.s3 = form.cleaned_data['s3']
            up.s4 = form.cleaned_data['s4']
            up.s5 = form.cleaned_data['s5']
            up.s6 = form.cleaned_data['s6']
            up.s7 = form.cleaned_data['s7']
            up.s8 = form.cleaned_data['s8']
            up.s9 = form.cleaned_data['s9']
            up.s10 = form.cleaned_data['s10']
            up.save()
            return redirect('log_in:attendance_list')
        else:
            print("Form Errors ", form.errors)

    else:
        up = get_object_or_404(AttendanceDB, pk=id)
        form = UpdateAttendanceForm(request.POST or None,instance=up)
    print("=============id===========",id)
    return render(request, 'log_in/update_attendance.html', {'form': form, 'id' : id})

def deleteattendance(request):
    #To Delete the Attendance Record
    user_id = request.GET.get('user_id', None)
    instance = AttendanceDB.objects.get(pk=int(user_id))
    instance.delete()
    data = {'qwe': 'asd'}
    return JsonResponse(data)


@login_required
def log_out(request):
    var = request.session['idid']
    print("======",var)
    o2 = LoginLogs.objects.get(id=var)
    o2.logout_time = datetime.datetime.now().isoformat()
    o2.save()
    logout(request)
    messages.success(request, 'Sucsessfully logged out.')
    return redirect('log_in:log_in')

from keras import backend as K
K.set_image_data_format('channels_first')
import h5py

_FLOATX = 'float32'


def TrainingModel(request):

    rollno = request.session['as_rollno']
    branch = request.session['as_branch']
    yod = request.session['as_yod']
    username = request.session['as_username']
    #np.set_printoptions(threshold=np.nan)
    # FRmodel = faceRecoModel(input_shape=(3, 96, 96))
    # count = 0
    #
    # # initialize the list to store the encoding of all the images in dataset
    # z = []
    # for i in os.listdir("/home/tanuj/project/major/application/log_in/majorpro/datasets/"+str(yod)+"/"+str(branch) +"/"+str(rollno)+"_"+str(username)+"/"):
    #     arr3 = img_to_encoding(os.path.join("/home/tanuj/project/major/application/log_in/majorpro/datasets/"+str(yod)+"/"+str(branch) +"/"+str(rollno)+"_"+str(username)+"/", i),FRmodel)
    #     # append encoding of individual images in list
    #     count = count + 1
    #     z.append(arr3)
    #
    # # convert the list into numpy array
    # zr = np.array(z)
    # # find the sum of all encoding element wise
    # z_sum = np.sum(zr, axis=0)
    # # find the average
    # z_mean = z_sum / count
    # # print(z_mean)

    known_image = face_recognition.load_image_file("/home/tanuj/project/major/application/log_in/majorpro"
                                                   "/datasets/"+str(yod)+"/"+str(branch) +"/"+str(rollno)+"_"+str(username)+"/image.jpg")
    print(known_image)
    z_mean = face_recognition.face_encodings(known_image)[0]
    print("--------------",z_mean)

    try:
        user_obj = UserData.objects.get(rollno = request.session["rollno"])
        user_obj.foldername = z_mean
        user_obj.save()
    except Exception as e:

        print("---------",e)
        messages.error(request, 'Invalid Request')
        return HttpResponseRedirect(reverse('log_in:model_train'))
    return redirect('log_in:model_train')

def variable(value, dtype=_FLOATX, name=None):
    v = tf.Variable(np.asarray(value, dtype=dtype), name=name)
    # _get_session().run(v.initializer)
    return v


def shape(x):
    return x.get_shape()


def square(x):
    return tf.square(x)


def zeros(shape, dtype=_FLOATX, name=None):
    return variable(np.zeros(shape), dtype, name)


def concatenate(tensors, axis=-1):
    if axis < 0:
        axis = axis % len(tensors[0].get_shape())
    return tf.concat(axis, tensors)


def LRN2D(x):
    return tf.nn.lrn(x, alpha=1e-4, beta=0.75)


def conv2d_bn(x,
              layer=None,
              cv1_out=None,
              cv1_filter=(1, 1),
              cv1_strides=(1, 1),
              cv2_out=None,
              cv2_filter=(3, 3),
              cv2_strides=(1, 1),
              padding=None):
    num = '' if cv2_out == None else '1'
    tensor = Conv2D(cv1_out, cv1_filter, strides=cv1_strides, data_format='channels_first', name=layer + '_conv' + num)(
        x)
    tensor = BatchNormalization(axis=1, epsilon=0.00001, name=layer + '_bn' + num)(tensor)
    tensor = Activation('relu')(tensor)
    if padding == None:
        return tensor
    tensor = ZeroPadding2D(padding=padding, data_format='channels_first')(tensor)
    if cv2_out == None:
        return tensor
    tensor = Conv2D(cv2_out, cv2_filter, strides=cv2_strides, data_format='channels_first', name=layer + '_conv' + '2')(
        tensor)
    tensor = BatchNormalization(axis=1, epsilon=0.00001, name=layer + '_bn' + '2')(tensor)
    tensor = Activation('relu')(tensor)
    return tensor


WEIGHTS = [
    'conv1', 'bn1', 'conv2', 'bn2', 'conv3', 'bn3',
    'inception_3a_1x1_conv', 'inception_3a_1x1_bn',
    'inception_3a_pool_conv', 'inception_3a_pool_bn',
    'inception_3a_5x5_conv1', 'inception_3a_5x5_conv2', 'inception_3a_5x5_bn1', 'inception_3a_5x5_bn2',
    'inception_3a_3x3_conv1', 'inception_3a_3x3_conv2', 'inception_3a_3x3_bn1', 'inception_3a_3x3_bn2',
    'inception_3b_3x3_conv1', 'inception_3b_3x3_conv2', 'inception_3b_3x3_bn1', 'inception_3b_3x3_bn2',
    'inception_3b_5x5_conv1', 'inception_3b_5x5_conv2', 'inception_3b_5x5_bn1', 'inception_3b_5x5_bn2',
    'inception_3b_pool_conv', 'inception_3b_pool_bn',
    'inception_3b_1x1_conv', 'inception_3b_1x1_bn',
    'inception_3c_3x3_conv1', 'inception_3c_3x3_conv2', 'inception_3c_3x3_bn1', 'inception_3c_3x3_bn2',
    'inception_3c_5x5_conv1', 'inception_3c_5x5_conv2', 'inception_3c_5x5_bn1', 'inception_3c_5x5_bn2',
    'inception_4a_3x3_conv1', 'inception_4a_3x3_conv2', 'inception_4a_3x3_bn1', 'inception_4a_3x3_bn2',
    'inception_4a_5x5_conv1', 'inception_4a_5x5_conv2', 'inception_4a_5x5_bn1', 'inception_4a_5x5_bn2',
    'inception_4a_pool_conv', 'inception_4a_pool_bn',
    'inception_4a_1x1_conv', 'inception_4a_1x1_bn',
    'inception_4e_3x3_conv1', 'inception_4e_3x3_conv2', 'inception_4e_3x3_bn1', 'inception_4e_3x3_bn2',
    'inception_4e_5x5_conv1', 'inception_4e_5x5_conv2', 'inception_4e_5x5_bn1', 'inception_4e_5x5_bn2',
    'inception_5a_3x3_conv1', 'inception_5a_3x3_conv2', 'inception_5a_3x3_bn1', 'inception_5a_3x3_bn2',
    'inception_5a_pool_conv', 'inception_5a_pool_bn',
    'inception_5a_1x1_conv', 'inception_5a_1x1_bn',
    'inception_5b_3x3_conv1', 'inception_5b_3x3_conv2', 'inception_5b_3x3_bn1', 'inception_5b_3x3_bn2',
    'inception_5b_pool_conv', 'inception_5b_pool_bn',
    'inception_5b_1x1_conv', 'inception_5b_1x1_bn',
    'dense_layer'
]

conv_shape = {
    'conv1': [64, 3, 7, 7],
    'conv2': [64, 64, 1, 1],
    'conv3': [192, 64, 3, 3],
    'inception_3a_1x1_conv': [64, 192, 1, 1],
    'inception_3a_pool_conv': [32, 192, 1, 1],
    'inception_3a_5x5_conv1': [16, 192, 1, 1],
    'inception_3a_5x5_conv2': [32, 16, 5, 5],
    'inception_3a_3x3_conv1': [96, 192, 1, 1],
    'inception_3a_3x3_conv2': [128, 96, 3, 3],
    'inception_3b_3x3_conv1': [96, 256, 1, 1],
    'inception_3b_3x3_conv2': [128, 96, 3, 3],
    'inception_3b_5x5_conv1': [32, 256, 1, 1],
    'inception_3b_5x5_conv2': [64, 32, 5, 5],
    'inception_3b_pool_conv': [64, 256, 1, 1],
    'inception_3b_1x1_conv': [64, 256, 1, 1],
    'inception_3c_3x3_conv1': [128, 320, 1, 1],
    'inception_3c_3x3_conv2': [256, 128, 3, 3],
    'inception_3c_5x5_conv1': [32, 320, 1, 1],
    'inception_3c_5x5_conv2': [64, 32, 5, 5],
    'inception_4a_3x3_conv1': [96, 640, 1, 1],
    'inception_4a_3x3_conv2': [192, 96, 3, 3],
    'inception_4a_5x5_conv1': [32, 640, 1, 1, ],
    'inception_4a_5x5_conv2': [64, 32, 5, 5],
    'inception_4a_pool_conv': [128, 640, 1, 1],
    'inception_4a_1x1_conv': [256, 640, 1, 1],
    'inception_4e_3x3_conv1': [160, 640, 1, 1],
    'inception_4e_3x3_conv2': [256, 160, 3, 3],
    'inception_4e_5x5_conv1': [64, 640, 1, 1],
    'inception_4e_5x5_conv2': [128, 64, 5, 5],
    'inception_5a_3x3_conv1': [96, 1024, 1, 1],
    'inception_5a_3x3_conv2': [384, 96, 3, 3],
    'inception_5a_pool_conv': [96, 1024, 1, 1],
    'inception_5a_1x1_conv': [256, 1024, 1, 1],
    'inception_5b_3x3_conv1': [96, 736, 1, 1],
    'inception_5b_3x3_conv2': [384, 96, 3, 3],
    'inception_5b_pool_conv': [96, 736, 1, 1],
    'inception_5b_1x1_conv': [256, 736, 1, 1],
}


def load_weights_from_FaceNet(FRmodel):
    # Load weights from csv files (which was exported from Openface torch model)
    weights = WEIGHTS
    weights_dict = load_weights()

    # Set layer weights of the model
    for name in weights:
        if FRmodel.get_layer(name) != None:
            FRmodel.get_layer(name).set_weights(weights_dict[name])



def load_weights():
    # Set weights path
    dirPath = './weights'
    fileNames = filter(lambda f: not f.startswith('.'), os.listdir(dirPath))
    paths = {}
    weights_dict = {}

    for n in fileNames:
        paths[n.replace('.csv', '')] = dirPath + '/' + n

    for name in WEIGHTS:
        if 'conv' in name:
            conv_w = genfromtxt(paths[name + '_w'], delimiter=',', dtype=None)
            conv_w = np.reshape(conv_w, conv_shape[name])
            conv_w = np.transpose(conv_w, (2, 3, 1, 0))
            conv_b = genfromtxt(paths[name + '_b'], delimiter=',', dtype=None)
            weights_dict[name] = [conv_w, conv_b]
        elif 'bn' in name:
            bn_w = genfromtxt(paths[name + '_w'], delimiter=',', dtype=None)
            bn_b = genfromtxt(paths[name + '_b'], delimiter=',', dtype=None)
            bn_m = genfromtxt(paths[name + '_m'], delimiter=',', dtype=None)
            bn_v = genfromtxt(paths[name + '_v'], delimiter=',', dtype=None)
            weights_dict[name] = [bn_w, bn_b, bn_m, bn_v]
        elif 'dense' in name:
            dense_w = genfromtxt(dirPath + '/dense_w.csv', delimiter=',', dtype=None)
            dense_w = np.reshape(dense_w, (128, 736))
            dense_w = np.transpose(dense_w, (1, 0))
            dense_b = genfromtxt(dirPath + '/dense_b.csv', delimiter=',', dtype=None)
            weights_dict[name] = [dense_w, dense_b]

    return weights_dict


def load_dataset():
    train_dataset = h5py.File('datasets/train_happy.h5', "r")
    train_set_x_orig = np.array(train_dataset["train_set_x"][:])  # your train set features
    train_set_y_orig = np.array(train_dataset["train_set_y"][:])  # your train set labels

    test_dataset = h5py.File('datasets/test_happy.h5', "r")
    test_set_x_orig = np.array(test_dataset["test_set_x"][:])  # your test set features
    test_set_y_orig = np.array(test_dataset["test_set_y"][:])  # your test set labels

    classes = np.array(test_dataset["list_classes"][:])  # the list of classes

    train_set_y_orig = train_set_y_orig.reshape((1, train_set_y_orig.shape[0]))
    test_set_y_orig = test_set_y_orig.reshape((1, test_set_y_orig.shape[0]))

    return train_set_x_orig, train_set_y_orig, test_set_x_orig, test_set_y_orig, classes


def img_to_encoding(image_path, model):
    img1 = cv2.imread(image_path, 1)
    img = img1[..., ::-1]
    img = np.around(np.transpose(img, (2, 0, 1)) / 255.0, decimals=12)
    x_train = np.array([img])
    embedding = model.predict_on_batch(x_train)
    return embedding

import tensorflow as tf
import numpy as np
import os
from numpy import genfromtxt
from keras import backend as K
from keras.layers import Conv2D, ZeroPadding2D, Activation, Input, concatenate
from keras.models import Model
from keras.layers.normalization import BatchNormalization
from keras.layers.pooling import MaxPooling2D, AveragePooling2D
from keras.layers.core import Lambda, Flatten, Dense


def inception_block_1a(X):
    """
    Implementation of an inception block
    """

    X_3x3 = Conv2D(96, (1, 1), data_format='channels_first', name='inception_3a_3x3_conv1')(X)
    X_3x3 = BatchNormalization(axis=1, epsilon=0.00001, name='inception_3a_3x3_bn1')(X_3x3)
    X_3x3 = Activation('relu')(X_3x3)
    X_3x3 = ZeroPadding2D(padding=(1, 1), data_format='channels_first')(X_3x3)
    X_3x3 = Conv2D(128, (3, 3), data_format='channels_first', name='inception_3a_3x3_conv2')(X_3x3)
    X_3x3 = BatchNormalization(axis=1, epsilon=0.00001, name='inception_3a_3x3_bn2')(X_3x3)
    X_3x3 = Activation('relu')(X_3x3)

    X_5x5 = Conv2D(16, (1, 1), data_format='channels_first', name='inception_3a_5x5_conv1')(X)
    X_5x5 = BatchNormalization(axis=1, epsilon=0.00001, name='inception_3a_5x5_bn1')(X_5x5)
    X_5x5 = Activation('relu')(X_5x5)
    X_5x5 = ZeroPadding2D(padding=(2, 2), data_format='channels_first')(X_5x5)
    X_5x5 = Conv2D(32, (5, 5), data_format='channels_first', name='inception_3a_5x5_conv2')(X_5x5)
    X_5x5 = BatchNormalization(axis=1, epsilon=0.00001, name='inception_3a_5x5_bn2')(X_5x5)
    X_5x5 = Activation('relu')(X_5x5)

    X_pool = MaxPooling2D(pool_size=3, strides=2, data_format='channels_first')(X)
    X_pool = Conv2D(32, (1, 1), data_format='channels_first', name='inception_3a_pool_conv')(X_pool)
    X_pool = BatchNormalization(axis=1, epsilon=0.00001, name='inception_3a_pool_bn')(X_pool)
    X_pool = Activation('relu')(X_pool)
    X_pool = ZeroPadding2D(padding=((3, 4), (3, 4)), data_format='channels_first')(X_pool)

    X_1x1 = Conv2D(64, (1, 1), data_format='channels_first', name='inception_3a_1x1_conv')(X)
    X_1x1 = BatchNormalization(axis=1, epsilon=0.00001, name='inception_3a_1x1_bn')(X_1x1)
    X_1x1 = Activation('relu')(X_1x1)

    # CONCAT
    inception = concatenate([X_3x3, X_5x5, X_pool, X_1x1], axis=1)

    return inception


def inception_block_1b(X):
    X_3x3 = Conv2D(96, (1, 1), data_format='channels_first', name='inception_3b_3x3_conv1')(X)
    X_3x3 = BatchNormalization(axis=1, epsilon=0.00001, name='inception_3b_3x3_bn1')(X_3x3)
    X_3x3 = Activation('relu')(X_3x3)
    X_3x3 = ZeroPadding2D(padding=(1, 1), data_format='channels_first')(X_3x3)
    X_3x3 = Conv2D(128, (3, 3), data_format='channels_first', name='inception_3b_3x3_conv2')(X_3x3)
    X_3x3 = BatchNormalization(axis=1, epsilon=0.00001, name='inception_3b_3x3_bn2')(X_3x3)
    X_3x3 = Activation('relu')(X_3x3)

    X_5x5 = Conv2D(32, (1, 1), data_format='channels_first', name='inception_3b_5x5_conv1')(X)
    X_5x5 = BatchNormalization(axis=1, epsilon=0.00001, name='inception_3b_5x5_bn1')(X_5x5)
    X_5x5 = Activation('relu')(X_5x5)
    X_5x5 = ZeroPadding2D(padding=(2, 2), data_format='channels_first')(X_5x5)
    X_5x5 = Conv2D(64, (5, 5), data_format='channels_first', name='inception_3b_5x5_conv2')(X_5x5)
    X_5x5 = BatchNormalization(axis=1, epsilon=0.00001, name='inception_3b_5x5_bn2')(X_5x5)
    X_5x5 = Activation('relu')(X_5x5)

    X_pool = AveragePooling2D(pool_size=(3, 3), strides=(3, 3), data_format='channels_first')(X)
    X_pool = Conv2D(64, (1, 1), data_format='channels_first', name='inception_3b_pool_conv')(X_pool)
    X_pool = BatchNormalization(axis=1, epsilon=0.00001, name='inception_3b_pool_bn')(X_pool)
    X_pool = Activation('relu')(X_pool)
    X_pool = ZeroPadding2D(padding=(4, 4), data_format='channels_first')(X_pool)

    X_1x1 = Conv2D(64, (1, 1), data_format='channels_first', name='inception_3b_1x1_conv')(X)
    X_1x1 = BatchNormalization(axis=1, epsilon=0.00001, name='inception_3b_1x1_bn')(X_1x1)
    X_1x1 = Activation('relu')(X_1x1)

    inception = concatenate([X_3x3, X_5x5, X_pool, X_1x1], axis=1)

    return inception


def inception_block_1c(X):
    X_3x3 = conv2d_bn(X,
                               layer='inception_3c_3x3',
                               cv1_out=128,
                               cv1_filter=(1, 1),
                               cv2_out=256,
                               cv2_filter=(3, 3),
                               cv2_strides=(2, 2),
                               padding=(1, 1))

    X_5x5 = conv2d_bn(X,
                               layer='inception_3c_5x5',
                               cv1_out=32,
                               cv1_filter=(1, 1),
                               cv2_out=64,
                               cv2_filter=(5, 5),
                               cv2_strides=(2, 2),
                               padding=(2, 2))

    X_pool = MaxPooling2D(pool_size=3, strides=2, data_format='channels_first')(X)
    X_pool = ZeroPadding2D(padding=((0, 1), (0, 1)), data_format='channels_first')(X_pool)

    inception = concatenate([X_3x3, X_5x5, X_pool], axis=1)

    return inception


def inception_block_2a(X):
    X_3x3 = conv2d_bn(X,
                               layer='inception_4a_3x3',
                               cv1_out=96,
                               cv1_filter=(1, 1),
                               cv2_out=192,
                               cv2_filter=(3, 3),
                               cv2_strides=(1, 1),
                               padding=(1, 1))
    X_5x5 = conv2d_bn(X,
                               layer='inception_4a_5x5',
                               cv1_out=32,
                               cv1_filter=(1, 1),
                               cv2_out=64,
                               cv2_filter=(5, 5),
                               cv2_strides=(1, 1),
                               padding=(2, 2))

    X_pool = AveragePooling2D(pool_size=(3, 3), strides=(3, 3), data_format='channels_first')(X)
    X_pool = conv2d_bn(X_pool,
                                layer='inception_4a_pool',
                                cv1_out=128,
                                cv1_filter=(1, 1),
                                padding=(2, 2))
    X_1x1 = conv2d_bn(X,
                               layer='inception_4a_1x1',
                               cv1_out=256,
                               cv1_filter=(1, 1))
    inception = concatenate([X_3x3, X_5x5, X_pool, X_1x1], axis=1)

    return inception


def inception_block_2b(X):
    # inception4e
    X_3x3 = conv2d_bn(X,
                               layer='inception_4e_3x3',
                               cv1_out=160,
                               cv1_filter=(1, 1),
                               cv2_out=256,
                               cv2_filter=(3, 3),
                               cv2_strides=(2, 2),
                               padding=(1, 1))
    X_5x5 = conv2d_bn(X,
                               layer='inception_4e_5x5',
                               cv1_out=64,
                               cv1_filter=(1, 1),
                               cv2_out=128,
                               cv2_filter=(5, 5),
                               cv2_strides=(2, 2),
                               padding=(2, 2))

    X_pool = MaxPooling2D(pool_size=3, strides=2, data_format='channels_first')(X)
    X_pool = ZeroPadding2D(padding=((0, 1), (0, 1)), data_format='channels_first')(X_pool)

    inception = concatenate([X_3x3, X_5x5, X_pool], axis=1)

    return inception


def inception_block_3a(X):
    X_3x3 = conv2d_bn(X,
                               layer='inception_5a_3x3',
                               cv1_out=96,
                               cv1_filter=(1, 1),
                               cv2_out=384,
                               cv2_filter=(3, 3),
                               cv2_strides=(1, 1),
                               padding=(1, 1))
    X_pool = AveragePooling2D(pool_size=(3, 3), strides=(3, 3), data_format='channels_first')(X)
    X_pool = conv2d_bn(X_pool,
                                layer='inception_5a_pool',
                                cv1_out=96,
                                cv1_filter=(1, 1),
                                padding=(1, 1))
    X_1x1 = conv2d_bn(X,
                               layer='inception_5a_1x1',
                               cv1_out=256,
                               cv1_filter=(1, 1))

    inception = concatenate([X_3x3, X_pool, X_1x1], axis=1)

    return inception


def inception_block_3b(X):
    X_3x3 = conv2d_bn(X,
                               layer='inception_5b_3x3',
                               cv1_out=96,
                               cv1_filter=(1, 1),
                               cv2_out=384,
                               cv2_filter=(3, 3),
                               cv2_strides=(1, 1),
                               padding=(1, 1))
    X_pool = MaxPooling2D(pool_size=3, strides=2, data_format='channels_first')(X)
    X_pool = conv2d_bn(X_pool,
                                layer='inception_5b_pool',
                                cv1_out=96,
                                cv1_filter=(1, 1))
    X_pool = ZeroPadding2D(padding=(1, 1), data_format='channels_first')(X_pool)

    X_1x1 = conv2d_bn(X,
                               layer='inception_5b_1x1',
                               cv1_out=256,
                               cv1_filter=(1, 1))
    inception = concatenate([X_3x3, X_pool, X_1x1], axis=1)

    return inception


def faceRecoModel(input_shape):
    """
    Implementation of the Inception model used for FaceNet

    Arguments:
    input_shape -- shape of the images of the dataset

    Returns:
    model -- a Model() instance in Keras
    """

    # Define the input as a tensor with shape input_shape
    X_input = Input(input_shape)

    # Zero-Padding
    X = ZeroPadding2D((3, 3))(X_input)

    # First Block
    X = Conv2D(64, (7, 7), strides=(2, 2), name='conv1')(X)
    X = BatchNormalization(axis=1, name='bn1')(X)
    X = Activation('relu')(X)

    # Zero-Padding + MAXPOOL
    X = ZeroPadding2D((1, 1))(X)
    X = MaxPooling2D((3, 3), strides=2)(X)

    # Second Block
    X = Conv2D(64, (1, 1), strides=(1, 1), name='conv2')(X)
    X = BatchNormalization(axis=1, epsilon=0.00001, name='bn2')(X)
    X = Activation('relu')(X)

    # Zero-Padding + MAXPOOL
    X = ZeroPadding2D((1, 1))(X)

    # Second Block
    X = Conv2D(192, (3, 3), strides=(1, 1), name='conv3')(X)
    X = BatchNormalization(axis=1, epsilon=0.00001, name='bn3')(X)
    X = Activation('relu')(X)

    # Zero-Padding + MAXPOOL
    X = ZeroPadding2D((1, 1))(X)
    X = MaxPooling2D(pool_size=3, strides=2)(X)

    # Inception 1: a/b/c
    X = inception_block_1a(X)
    X = inception_block_1b(X)
    X = inception_block_1c(X)

    # Inception 2: a/b
    X = inception_block_2a(X)
    X = inception_block_2b(X)

    # Inception 3: a/b
    X = inception_block_3a(X)
    X = inception_block_3b(X)

    # Top layer
    X = AveragePooling2D(pool_size=(3, 3), strides=(1, 1), data_format='channels_first')(X)
    X = Flatten()(X)
    X = Dense(128, name='dense_layer')(X)

    # L2 normalization
    X = Lambda(lambda x: K.l2_normalize(x, axis=1))(X)

    # Create model instance
    model = Model(inputs=X_input, outputs=X, name='FaceRecoModel')

    return model
