package com.upgrad.quora.service.dao;

import com.upgrad.quora.service.entity.UserAuthEntity;
import com.upgrad.quora.service.entity.UserEntity;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.PersistenceContext;

@Repository
public class UserDao {

    @PersistenceContext
    private EntityManager entityManager;

    //Persist a user in database
    public UserEntity createUser(UserEntity userEntity) {
        entityManager.persist(userEntity);
        return userEntity;
    }

    //Get user by enmail
    public UserEntity getUserByEmail(final String email) {
        try {
            return entityManager.createNamedQuery("userByEmail", UserEntity.class).setParameter("email", email).getSingleResult();
        } catch (NoResultException nre) {
            return null;
        }
    }

    //Get user by user name
    public UserEntity getUserByUserName(final String userName) {
        try {
            return entityManager.createNamedQuery("userByUserName", UserEntity.class).setParameter("userName", userName).getSingleResult();
        } catch (NoResultException nre) {
            return null;
        }
    }

    //Get user by uuid
    public UserEntity getuserByUuid(final String uuid) {
        try {
            return entityManager.createNamedQuery("userByUuid", UserEntity.class).setParameter("uuid", uuid).getSingleResult();
        } catch (NoResultException nre) {
            return null;
        }
    }

    //Create auth token
    public UserAuthEntity createAuthToken(final UserAuthEntity userAuthTokenEntity) {
        entityManager.persist(userAuthTokenEntity);
        return userAuthTokenEntity;
    }

    //Get userAuth by token
    public UserAuthEntity getUserAuthByToken(final String authToken) {
        try {
            return entityManager.createNamedQuery("userAuthTokenByAccessToken", UserAuthEntity.class).setParameter("accessToken", authToken).getSingleResult();
        } catch (NoResultException nre) {
            return null;
        }
    }

    //Get userAuth by User
    public UserAuthEntity getUserAuthByUser(final UserEntity userEntity) {
        try {
            return entityManager.createNamedQuery("userAuthTokenByUser", UserAuthEntity.class).setParameter("user", userEntity).getSingleResult();
        } catch (NoResultException nre) {
            return null;
        }
    }
    // Updates userAuth
    public void updateUserAuth(final UserAuthEntity updatedUserAuth) {
        entityManager.merge(updatedUserAuth);
    }
    // deletes user
    public void deleteUser(final UserEntity updatedUserEntity) {
        entityManager.remove(updatedUserEntity);
    }
}
