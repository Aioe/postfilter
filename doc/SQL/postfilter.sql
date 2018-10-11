use postfilter;
CREATE TABLE `postfilter` (
`ID` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY ,
`time` BIGINT NOT NULL ,
`domain` MEDIUMTEXT NOT NULL ,
`error_code` INT NOT NULL ,
`length` INT NOT NULL ,
`head_length` INT NOT NULL ,
`groups` INT NOT NULL ,
`followups` INT NOT NULL ,
`user` MEDIUMTEXT NOT NULL ,
`md5` MEDIUMTEXT NOT NULL ,
`IP` MEDIUMTEXT NOT NULL
) ENGINE = MYISAM COMMENT = 'Posfilter Access Tables';
