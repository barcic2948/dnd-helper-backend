-- Insert data into APPLICATION_USER table
INSERT INTO APPLICATION_USER (id, username, role)
VALUES
(1, 'user1', 'USER'),
(2, 'user2', 'ADMIN'),
(3, 'user3', 'USER'),
(4, 'user4', 'USER'),
(5, 'user5', 'ADMIN'),
(6, 'user6', 'USER'),
(7, 'user7', 'USER'),
(8, 'user8', 'ADMIN'),
(9, 'user9', 'USER'),
(10, 'user10', 'ADMIN');

-- Insert data into BASIC_AUTH_USER table
INSERT INTO BASIC_AUTH_USER (id, application_user_id, password)
VALUES
(1, 1, 'password1'),
(2, 2, 'password2'),
(3, 3, 'password3'),
(4, 4, 'password4'),
(5, 5, 'password5'),
(6, 6, 'password6'),
(7, 7, 'password7'),
(8, 8, 'password8'),
(9, 9, 'password9'),
(10, 10, 'password10');