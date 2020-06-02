package com.upgrad.quora.service.business;

import com.upgrad.quora.service.dao.UserDao;
import com.upgrad.quora.service.entity.UserAuthEntity;
import com.upgrad.quora.service.entity.UserEntity;
import com.upgrad.quora.service.exception.AuthorizationFailedException;
import com.upgrad.quora.service.exception.UserNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CommonService {

    @Autowired
    private UserDao userDao;

    /**Service to get User details.
     * @param uuid user uuid
     * @param authorization authrization
     * @return UserAuthEntity
     * @throws AuthorizationFailedException AuthorizationFailedException
     */
    public UserEntity getUser(final String uuid, final String authorization) throws AuthorizationFailedException, UserNotFoundException {

        UserEntity userByID = userDao.getuserByUuid(uuid);
        UserAuthEntity userAuth = userDao.getUserAuthByToken(authorization);
        if(userAuth == null){
            throw new AuthorizationFailedException("ATHR-001","User has not signed in");
        }
        if(userAuth.getLogoutAt() != null){
            throw new AuthorizationFailedException("ATHR-002","User is signed out.Sign in first to get user details");
        }
        if(userByID == null){
            throw new UserNotFoundException("USR-001","User with entered uuid does not exist");
        }

        return userByID;
    }

}
