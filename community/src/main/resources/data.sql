insert into `Member`
    (`created_at`,`modified_at`, `email`, `gender`, `major`, `name`, `nick_name`, `password`, `profile`,`role` ,`student_id`, `type`)
    value (
           now(),now(), 'test@naver.com', 'male', 'computer', '홍길동', 'nick_name',
           '$2a$12$oqvPxc4s2oNHWF9dVJxARug/8V6IOqrI7ljtsAt89PpCGY6nqpKpC', 'profile','ROLE_USER','L190201201','GENERAL'
          );

insert into `Member`
(`created_at`,`modified_at`, `email`, `gender`, `major`, `name`, `nick_name`, `profile`,`role` ,`student_id`, `type`)
    value (
           now(),now(), 'jaeseonnamgung@gmail.com', 'male', 'computer', '남궁재선', 'nick_name',
            'https://lh3.googleusercontent.com/a/ACg8ocI4HIQ-ippnF0Fl0bTHpERVBY8dcYNNkZks3l7XCY3B=s96-c','ROLE_USER',
           'L190201201', 'GOOGLE'
    );
# insert into `Member`
#       (`created_at`,`modified_at`, `email`, `gender`, `major`, `name`, `nick_name`, `profile`,`role` ,`student_id`, `type`)
#           value (
#                  now(),now(), 'sunnamgung8@naver.com', 'male', 'computer', '남궁재선', 'nick_name',
#                  'https://ssl.pstatic.net/static/pwe/address/img_profile.png','ROLE_USER','L190201201',
#                  'NAVER'
#         );