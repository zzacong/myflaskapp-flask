DROP DATABASE IF EXISTS `myflaskapp`;

CREATE DATABASE `myflaskapp`;

USE `myflaskapp`;

DROP TABLE IF EXISTS `users`;

CREATE TABLE `users` (
  `id` SERIAL,
  `name` VARCHAR(100),
  `email` VARCHAR(255),
  `username` VARCHAR(30),
  `password` VARCHAR(100),
  `register_date` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
);