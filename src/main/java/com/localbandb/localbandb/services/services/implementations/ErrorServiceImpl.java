package com.localbandb.localbandb.services.services.implementations;

import com.localbandb.localbandb.data.models.CustomError;
import com.localbandb.localbandb.data.repositories.ErrorRepository;
import com.localbandb.localbandb.services.services.ErrorService;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class ErrorServiceImpl implements ErrorService {
    private final ErrorRepository errorRepository;

    public ErrorServiceImpl(ErrorRepository errorRepository) {
        this.errorRepository = errorRepository;
    }

    @Override
    public void saveError(Exception ex) {
        CustomError error = new CustomError();
        String stack = "No Stack Trace";
        StackTraceElement[] stackTraceArr = ex.getStackTrace();
        if(stackTraceArr.length > 0) {
            StackTraceElement stackTrace = ex.getStackTrace()[0];
            stack = String.format("%s//, %s//, %s//, %s//, %s//, %s//, %s", stackTrace.getClassLoaderName(), stackTrace.getClassName(),
                    stackTrace.getModuleName(), stackTrace.getModuleVersion(), stackTrace.getFileName(), stackTrace.getLineNumber(),
                    stackTrace.getMethodName());
            error.setException(ex.toString());
        }

        error.setStackTrace(stack);
        error.setDateTime(LocalDateTime.now());
        errorRepository.saveAndFlush(error);
    }
}
