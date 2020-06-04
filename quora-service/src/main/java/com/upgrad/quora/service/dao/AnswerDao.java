package com.upgrad.quora.service.dao;

import com.upgrad.quora.service.entity.Answer;
import com.upgrad.quora.service.entity.Questions;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.PersistenceContext;
import java.util.List;

@Repository
public class AnswerDao {
    @PersistenceContext
    private EntityManager entityManager;

    public Answer createAnswer(Answer answer) {
        entityManager.persist(answer);
        return answer;
    }
    public List<Answer> getAllAnswer() {
        return entityManager.createQuery("SELECT a FROM Answer a", Answer.class)
                .getResultList();
    }
    public Answer editAnswer(final Answer answerEntity) {
        return entityManager.merge(answerEntity);
    }
    public Answer getAnswerByUuid(final String AnswerByUuid) {
        try {
            return entityManager.createNamedQuery("AnswerByUuid", Answer.class)
                    .setParameter("uuid", AnswerByUuid).getSingleResult();
        } catch (NoResultException nre) {
            return null;
        }
    }
    public Answer deleteAnswer(final Answer answerEntity) {
        entityManager.remove(answerEntity);
        return answerEntity;
    }
    public List<Answer> getAnswersByQuestion(final Questions question){
        try {
            return entityManager.createNamedQuery("getAnswersByQuestion", Answer.class)
                    .setParameter("question",question ).getResultList();
        } catch (NoResultException nre) {
            return null;
        }
    }
}