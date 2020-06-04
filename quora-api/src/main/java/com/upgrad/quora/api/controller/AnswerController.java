package com.upgrad.quora.api.controller;

import com.upgrad.quora.api.model.*;
import com.upgrad.quora.service.business.AnswerService;
import com.upgrad.quora.service.business.AuthenticationService;
import com.upgrad.quora.service.entity.Answer;
import com.upgrad.quora.service.exception.AnswerNotFoundException;
import com.upgrad.quora.service.exception.AuthorizationFailedException;
import com.upgrad.quora.service.exception.InvalidQuestionException;
import com.upgrad.quora.service.exception.UserNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Controller
public class AnswerController {

    @Autowired
    private AnswerService answerService;

    @Autowired
    private AuthenticationService authenticationService;

    @RequestMapping(method = RequestMethod.POST, path =  "/question/{questionId}/answer/create", consumes = MediaType.APPLICATION_JSON_UTF8_VALUE, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<AnswerResponse> answerCreate(final AnswerRequest answerRequest, @PathVariable("questionId") final String questionId, @RequestHeader("authorization") final String authorization) throws AuthorizationFailedException, UserNotFoundException, InvalidQuestionException {
        //set parameters to answer object
        final Answer answer = new Answer();
        answer.setUuid(UUID.randomUUID().toString());
        answer.setAns(answerRequest.getAnswer());
        answer.setDate(ZonedDateTime.now());
        answer.setUuid(questionId);

        final Answer answerEntity = answerService.createAnswer(answer,questionId,authorization);
        AnswerResponse userResponse = new AnswerResponse().id(answerEntity.getUuid()).status("ANSWER CREATED");
        return new ResponseEntity<AnswerResponse>(userResponse, HttpStatus.CREATED);
    }

    @RequestMapping(method = RequestMethod.PUT,path = "/answer/edit/{answerId}",consumes = MediaType.APPLICATION_JSON_UTF8_VALUE,produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<AnswerEditResponse> answerEdit(@RequestHeader("authorization") final String authorization,
                                                         @PathVariable("answerId") final String answerId, final AnswerEditRequest answerEditRequest) throws AuthorizationFailedException, AnswerNotFoundException {
        Answer answerEntity = answerService
                .editAnswer(answerEditRequest.getContent(), answerId,authorization);
        AnswerEditResponse answerEditResponse = new AnswerEditResponse()
                .id(answerEntity.getUuid()).status("ANSWER EDITED");
        return new ResponseEntity<AnswerEditResponse>(answerEditResponse, HttpStatus.OK);
    }

    @RequestMapping(method = RequestMethod.DELETE,path = "/answer/delete/{answerId}",produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<AnswerDeleteResponse> answerDelete(@RequestHeader("authorization") final String authorization,
                                                             @PathVariable("answerId") final String answerId) throws AuthorizationFailedException, AnswerNotFoundException {
        Answer answerEntity =answerService.deleteAnswer(answerId,authorization);
        AnswerDeleteResponse answerDeleteResponse=new AnswerDeleteResponse()
                .id(answerEntity.getUuid()).status("ANSWER DELETED");
        return new ResponseEntity<AnswerDeleteResponse>(answerDeleteResponse,HttpStatus.OK);
    }

    @RequestMapping(method = RequestMethod.GET,path = "/answer/all/{questionId}",produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<List<AnswerDetailsResponse>> getAllAnswer(@RequestHeader("authorization") final String authorization,
                                                                    @PathVariable("questionId") final String questionId) throws AuthorizationFailedException, AnswerNotFoundException, InvalidQuestionException {

        List<Answer> answerList =answerService.getAllAnswer(questionId,authorization);
        String questionContent=answerService.getQuestionContent(questionId);
        return getListResponseEntity(answerList,questionContent);
    }
    private ResponseEntity<List<AnswerDetailsResponse>> getListResponseEntity(
            List<Answer> answerList, String questionContent) {
        List<AnswerDetailsResponse> ent = new ArrayList<AnswerDetailsResponse>();
        for (Answer n : answerList) {
            AnswerDetailsResponse answerDetailsResponse = new AnswerDetailsResponse();
            answerDetailsResponse.id(n.getUuid());
            answerDetailsResponse.answerContent(n.getAns());
            answerDetailsResponse.questionContent(questionContent);
            ent.add(answerDetailsResponse);
        }

        return new ResponseEntity<List<AnswerDetailsResponse>>(ent, HttpStatus.OK);
    }
}