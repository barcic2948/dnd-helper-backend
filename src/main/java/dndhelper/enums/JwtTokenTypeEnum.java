package dndhelper.enums;

import lombok.Getter;

@Getter
public enum JwtTokenTypeEnum {
    BEARER("Bearer");

    private final String header;

    JwtTokenTypeEnum(String header) {
        this.header = header;
    }
}
